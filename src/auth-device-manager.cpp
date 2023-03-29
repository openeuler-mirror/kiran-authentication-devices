/**
 * Copyright (c) 2020 ~ 2021 KylinSec Co., Ltd.
 * kiran-biometrics is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *          http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 *
 * Author:     luoqing <luoqing@kylinsec.com.cn>
 */

#include "auth-device-manager.h"
#include <linux/netlink.h>
#include <qt5-log-i.h>
#include <QDBusConnection>
#include <QDBusError>
#include <QDBusMessage>
#include "device/auth-device.h"
#include "auth_device_manager_adaptor.h"
#include "context/context-factory.h"
#include "feature-db.h"
#include "kiran-auth-device-i.h"
#include "polkit-proxy.h"
#include "utils.h"

namespace Kiran
{
#define SUBSYSTEM "usb"

AuthDeviceManager::AuthDeviceManager(QObject* parent) : QObject(parent)
{
}

AuthDeviceManager::~AuthDeviceManager()
{
}

AuthDeviceManager* AuthDeviceManager::m_instance = nullptr;
void AuthDeviceManager::globalInit()
{
    m_instance = new AuthDeviceManager();
    m_instance->init();
}

QString AuthDeviceManager::GetDevices()
{
    auto devices = m_deviceMap.values();
    QJsonDocument jsonDoc;
    QJsonArray jsonArray;
    Q_FOREACH (AuthDevice* device, devices)
    {
        QJsonObject jsonObj{
            {"deviceType", device->deviceType()},
            {"deviceName", device->deviceName()},
            {"deviceID", device->deviceID()},
            {"objectPath", device->getObjectPath().path()}};
        jsonArray.append(jsonObj);
    }

    jsonDoc.setArray(jsonArray);
    return QString(jsonDoc.toJson(QJsonDocument::Compact));
}

QString AuthDeviceManager::GetDevicesByType(int device_type)
{
    auto devices = m_deviceMap.values();
    QJsonDocument jsonDoc;
    QJsonArray jsonArray;
    Q_FOREACH (AuthDevice* device, devices)
    {
        if (device->deviceType() == device_type)
        {
            QJsonObject jsonObj{
                {"deviceName", device->deviceName()},
                {"deviceID", device->deviceID()},
                {"objectPath", device->getObjectPath().path()}};
            jsonArray.append(jsonObj);
        }
    }
    jsonDoc.setArray(jsonArray);
    return QString(jsonDoc.toJson(QJsonDocument::Compact));
}

QDBusObjectPath AuthDeviceManager::GetDevice(const QString& device_id)
{
    auto devices = m_deviceMap.values();
    QDBusObjectPath objectPath;
    Q_FOREACH (AuthDevice* device, devices)
    {
        if (device->deviceID() == device_id)
        {
            objectPath = device->getObjectPath();
        }
    }
    return objectPath;
}

QStringList AuthDeviceManager::GetAllFeatureIDs()
{
    QStringList allFeatureIDs;
    auto devices = m_deviceMap.values();
    Q_FOREACH (AuthDevice* device, devices)
    {
        allFeatureIDs << device->GetFeatureIDList();
    }
    KLOG_DEBUG() << "allFeatureIDs:" << allFeatureIDs;
    return allFeatureIDs;
}

// FIXME:如果只从配置文件中获取驱动信息，则需要将libfprint中所有驱动信息写入到配置文件
QString AuthDeviceManager::GetDriversByType(int device_type)
{
    QJsonDocument jsonDoc;
    QJsonArray jsonArray;

    QSettings confSettings(DRIVERS_CONF, QSettings::NativeFormat);
    QStringList driverList = confSettings.childGroups();
    Q_FOREACH (auto driver, driverList)
    {
        confSettings.beginGroup(driver);
        QVariant varEnable = confSettings.value("Enable");
        QVariant varType = confSettings.value("Type");
        bool enable;
        if (varEnable.isValid() && (varEnable.toString() == "true"))
            enable = true;
        else
            enable = false;

        int type = (varType.isValid()) ? confSettings.value("Type").toInt() : -1;
        confSettings.endGroup();

        if (type == device_type)
        {
            QJsonObject jsonObj{
                {"driverName", driver},
                {"enable", enable}};
            jsonArray.append(jsonObj);
        }
    }
    jsonDoc.setArray(jsonArray);
    return QString(jsonDoc.toJson(QJsonDocument::Compact));
}

void AuthDeviceManager::onRemove(const QDBusMessage& message, const QString& feature_id)
{
    bool result = FeatureDB::getInstance()->deleteFeature(feature_id);
    KLOG_DEBUG() << "deleteFeature:" << feature_id
                 << "result" << result;
    auto replyMessage = message.createReply();
    QDBusConnection::systemBus().send(replyMessage);
}

// TODO:是否需要监听配置文件的改变
void AuthDeviceManager::onSetEnableDriver(const QDBusMessage& message, const QString& driver_name, bool enable)
{
    QSettings confSettings(DRIVERS_CONF, QSettings::NativeFormat);
    QStringList driverList = confSettings.childGroups();
    QString enableStr;
    if (driverList.contains(driver_name))
    {
        enableStr = enable ? QString("true") : QString("false");
        confSettings.setValue(QString("%1/Enable").arg(driver_name), QVariant(enableStr));
    }

    // 驱动被禁用，将当前正在使用的设备释放掉
    if (!enable && driverList.contains(driver_name))
    {
        auto devices = m_deviceMap.values();
        Q_FOREACH (AuthDevice* device, devices)
        {
            if (device->deviceDriver() == driver_name)
            {
                QString deviceID = device->deviceID();
                int deviceType = device->deviceType();
                device->deleteLater();
                QString key = m_deviceMap.key(device);
                m_deviceMap.remove(key);
                device = nullptr;
                Q_EMIT m_dbusAdaptor->DeviceDeleted(deviceType, deviceID);
            }
        }
    }
    auto replyMessage = message.createReply();
    QDBusConnection::systemBus().send(replyMessage);
}

CHECK_AUTH_WITH_1ARGS(AuthDeviceManager, Remove, onRemove, AUTH_USER_ADMIN, const QString&)
CHECK_AUTH_WITH_2ARGS(AuthDeviceManager, SetEnableDriver, onSetEnableDriver, AUTH_USER_ADMIN, const QString&, bool)

void AuthDeviceManager::init()
{
    m_dbusAdaptor = new AuthDeviceManagerAdaptor(this);
    m_contextFactory = ContextFactory::instance();
    m_timer = new QTimer(this);
    connect(m_timer, &QTimer::timeout, this, &AuthDeviceManager::handleDeviceReCreate);

    QDBusConnection dbusConnection = QDBusConnection::systemBus();
    if (!dbusConnection.registerService(AUTH_DEVICE_DBUS_NAME))
    {
        KLOG_ERROR() << "register Service error:" << dbusConnection.lastError().message();
    }
    else
    {
        if (dbusConnection.registerObject(AUTH_DEVICE_DBUS_OBJECT_PATH,
                                          AUTH_DEVICE_DBUS_INTERFACE_NAME,
                                          this))
        {
            KLOG_DEBUG() << "register Object:" << AUTH_DEVICE_DBUS_OBJECT_PATH;
        }
        else
            KLOG_ERROR() << "Can't register object:" << dbusConnection.lastError();
    }

    m_udev = udev_new();
    if (!m_udev)
    {
        KLOG_ERROR() << "new udev error";
    }

    initDeviceMonitor(m_udev);
    auto usbInfoList = enumerateDevices(m_udev);
    // 枚举设备后，生成设备对象
    Q_FOREACH (auto deviceInfo, usbInfoList)
    {
        if (m_contextFactory->isDeviceSupported(deviceInfo.idVendor, deviceInfo.idProduct))
        {
            AuthDevice* device = m_contextFactory->createDevice(deviceInfo.idVendor, deviceInfo.idProduct);
            if (device)
            {
                m_deviceMap.insert(deviceInfo.busPath, device);
            }
            else
            {
                handleDeviceCreateFail(deviceInfo);
            }
        }
    }
}

void AuthDeviceManager::initDeviceMonitor(struct udev* udev)
{
    // 创建一个新的monitor
    m_monitor = udev_monitor_new_from_netlink(udev, "udev");
    // 增加一个udev事件过滤器
    udev_monitor_filter_add_match_subsystem_devtype(m_monitor, "usb", nullptr);
    // 启动监控
    udev_monitor_enable_receiving(m_monitor);
    // 获取该监控的文件描述符，fd就代表了这个监控
    m_fd = udev_monitor_get_fd(m_monitor);

    m_socketNotifierRead = new QSocketNotifier(m_fd, QSocketNotifier::Read, this);
    connect(m_socketNotifierRead, &QSocketNotifier::activated, this, &AuthDeviceManager::handleSocketNotifierRead);
}

void AuthDeviceManager::handleSocketNotifierRead(int socket)
{
    fd_set fds;
    struct timeval tv;
    int ret;

    FD_ZERO(&fds);
    FD_SET(m_fd, &fds);
    tv.tv_sec = 0;
    tv.tv_usec = 10000;
    ret = select(m_fd + 1, &fds, nullptr, nullptr, &tv);

    // 判断是否有事件产生
    if (!ret)
        return;
    if (!FD_ISSET(m_fd, &fds))
        return;

    // 获取产生事件的设备映射
    struct udev_device* dev = udev_monitor_receive_device(m_monitor);
    if (!dev)
        return;

    // 获取事件并判断是否是插拔
    unsigned long long curNum = udev_device_get_devnum(dev);
    if (curNum <= 0)
    {
        udev_device_unref(dev);
        return;
    }

    /**
     * action 发生了以下操作：
     * add- 设备已连接到系统
     * remove- 设备与系统断开连接
     * change- 有关设备的某些内容已更改
     * move- 设备节点已移动、重命名或重新父级
     * bind
     * unbind
     */
    QString action = udev_device_get_action(dev);

    // 只有add和remove事件才会更新缓存信息
    if (action == "add")
    {
        DeviceInfo usbInfo;
        usbInfo.idVendor = udev_device_get_sysattr_value(dev, "idVendor");
        usbInfo.idProduct = udev_device_get_sysattr_value(dev, "idProduct");
        usbInfo.busPath = udev_device_get_devnode(dev);
        handleDeviceAdded(usbInfo);
    }
    else if (action == "remove")
    {
        // Note:设备拔除时，获取不到idVendor和idProduct
        handleDeviceDeleted();
    }
    udev_device_unref(dev);
}

QList<DeviceInfo> AuthDeviceManager::enumerateDevices(struct udev* udev)
{
    struct udev_enumerate* enumerate = udev_enumerate_new(udev);  // 创建一个枚举器用于扫描已连接的设备

    udev_enumerate_add_match_subsystem(enumerate, SUBSYSTEM);
    udev_enumerate_scan_devices(enumerate);

    struct udev_list_entry* devices = udev_enumerate_get_list_entry(enumerate);  // 返回一个存储了设备所有属性信息的链表
    struct udev_list_entry* entry;

    QList<DeviceInfo> usbInfoList;
    udev_list_entry_foreach(entry, devices)
    {
        const char* path = udev_list_entry_get_name(entry);
        struct udev_device* dev = udev_device_new_from_syspath(udev, path);  // 创建一个udev设备的映射
        DeviceInfo usbInfo;
        usbInfo.idVendor = udev_device_get_sysattr_value(dev, "idVendor");
        usbInfo.idProduct = udev_device_get_sysattr_value(dev, "idProduct");
        usbInfo.busPath = udev_device_get_devnode(dev);
        usbInfoList << usbInfo;

        // processDevice(dev);
    }

    udev_enumerate_unref(enumerate);
    return usbInfoList;
}

// NOTE:过滤设备，暂时先简单测试
void AuthDeviceManager::processDevice(struct udev_device* dev)
{
    if (dev)
    {
        if (udev_device_get_devnode(dev))
        {
            deviceSimpleInfo(dev);
        }
        udev_device_unref(dev);
    }
}

void AuthDeviceManager::deviceSimpleInfo(struct udev_device* dev)
{
    /**
     * action 发生了以下操作：
     * add- 设备已连接到系统
     * remove- 设备与系统断开连接
     * change- 有关设备的某些内容已更改
     * move- 设备节点已移动、重命名或重新父级
     */
    const char* action = udev_device_get_action(dev);
    if (!action)
        action = "exists";

    const char* vendor = udev_device_get_sysattr_value(dev, "idVendor");
    if (!vendor)
        vendor = "0000";

    const char* product = udev_device_get_sysattr_value(dev, "idProduct");
    if (!product)
        product = "0000";

    KLOG_DEBUG() << udev_device_get_subsystem(dev)
                 << udev_device_get_devtype(dev)
                 << action
                 << vendor
                 << product
                 << udev_device_get_devnode(dev);
}

void AuthDeviceManager::handleDeviceAdded(const DeviceInfo& deviceInfo)
{
    if (m_contextFactory->isDeviceSupported(deviceInfo.idVendor, deviceInfo.idProduct))
    {
        AuthDevice* device = m_contextFactory->createDevice(deviceInfo.idVendor, deviceInfo.idProduct);
        if (device)
        {
            m_deviceMap.insert(deviceInfo.busPath, device);
            Q_EMIT this->DeviceAdded(device->deviceType(), device->deviceID());
            Q_EMIT m_dbusAdaptor->DeviceAdded(device->deviceType(), device->deviceID());

            KLOG_DEBUG() << "auth device added"
                         << "idVendor:" << deviceInfo.idVendor
                         << "idProduct:" << deviceInfo.idProduct
                         << "bus:" << deviceInfo.busPath;
        }
        else
        {
            handleDeviceCreateFail(deviceInfo);
        }
    }
    else
    {
        KLOG_DEBUG() << "no auth device !"
                     << "idVendor:" << deviceInfo.idVendor
                     << "idProduct:" << deviceInfo.idProduct;
    }
}

void AuthDeviceManager::handleDeviceCreateFail(DeviceInfo deviceInfo)
{
    m_retreyCreateDeviceMap.insert(deviceInfo, 0);
    if (m_retreyCreateDeviceMap.count() != 0)
    {
        if (!m_timer->isActive())
        {
            m_timer->start(1000);
        }
    }
}

void AuthDeviceManager::handleDeviceDeleted()
{
    QList<DeviceInfo> newUsbInfoList = enumerateDevices(m_udev);
    QStringList newBusList;
    Q_FOREACH (auto newUsbInfo, newUsbInfoList)
    {
        newBusList << newUsbInfo.busPath;
    }

    QStringList oldBusList = m_deviceMap.keys();
    QString deviceID;
    int deviceType;
    Q_FOREACH (auto busPath, oldBusList)
    {
        if (!newBusList.contains(busPath))
        {
            AuthDevice* oldAuthDevice = m_deviceMap.value(busPath);
            deviceID = oldAuthDevice->deviceID();
            deviceType = oldAuthDevice->deviceType();
            oldAuthDevice->deleteLater();
            oldAuthDevice = nullptr;
            m_deviceMap.remove(busPath);
            QMapIterator<DeviceInfo, int> i(m_retreyCreateDeviceMap);
            while (i.hasNext())
            {
                i.next();
                if (i.key().busPath == busPath)
                {
                    m_retreyCreateDeviceMap.remove(i.key());
                }
            }
            KLOG_DEBUG() << "device delete: " << busPath;
            break;
        }
    }
    Q_EMIT m_dbusAdaptor->DeviceDeleted(deviceType, deviceID);
}

void AuthDeviceManager::handleDeviceReCreate()
{
    if (m_retreyCreateDeviceMap.count() == 0)
    {
        m_timer->stop();
    }
    else
    {
        QMapIterator<DeviceInfo, int> i(m_retreyCreateDeviceMap);
        while (i.hasNext())
        {
            i.next();
            if (i.value() >= 2)
            {
                m_retreyCreateDeviceMap.remove(i.key());
            }
            else
            {
                auto deviceInfo = i.key();
                AuthDevice* device = m_contextFactory->createDevice(deviceInfo.idVendor, deviceInfo.idProduct);
                if (device)
                {
                    m_deviceMap.insert(deviceInfo.busPath, device);
                    Q_EMIT this->DeviceAdded(device->deviceType(), device->deviceID());
                    Q_EMIT m_dbusAdaptor->DeviceAdded(device->deviceType(), device->deviceID());

                    KLOG_DEBUG() << "device added"
                                 << "idVendor:" << deviceInfo.idVendor
                                 << "idProduct:" << deviceInfo.idProduct
                                 << "bus:" << deviceInfo.busPath;

                    m_retreyCreateDeviceMap.remove(i.key());
                }
                else
                {
                    m_retreyCreateDeviceMap.insert(i.key(), i.value() + 1);
                }
            }
        }
    }
}
}  // namespace Kiran
