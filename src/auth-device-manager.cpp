/**
 * Copyright (c) 2020 ~ 2021 KylinSec Co., Ltd.
 * kiran-authentication-devices is licensed under Mulan PSL v2.
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
#include "auth_device_manager_adaptor.h"
#include "config-helper.h"
#include "config.h"
#include "device/auth-device.h"
#include "device/device-creator.h"
#include "device/ukey/ukey-skf-device.h"
#include "driver/driver-factory.h"
#include "feature-db.h"
#include "kiran-auth-device-i.h"
#include "polkit-proxy.h"
#include "utils.h"

namespace Kiran
{

#define MAX_RETREY_CREATE_COUNT 2

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
    Q_FOREACH (AuthDevicePtr device, devices)
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
    Q_FOREACH (AuthDevicePtr device, devices)
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
    Q_FOREACH (AuthDevicePtr device, devices)
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
    QStringList allFeatureIDs = FeatureDB::getInstance()->getAllFeatureIDs();
    KLOG_DEBUG() << "allFeatureIDs:" << allFeatureIDs;
    return allFeatureIDs;
}

// FIXME:如果只从配置文件中获取驱动信息，则需要将libfprint中所有驱动信息写入到配置文件
QString AuthDeviceManager::GetDriversByType(int device_type)
{
    QJsonDocument jsonDoc;
    QJsonArray jsonArray;
    QSettings confSettings(DRIVER_CONF, QSettings::NativeFormat);
    QStringList driverList = confSettings.childGroups();
    Q_FOREACH (auto driver, driverList)
    {
        confSettings.beginGroup(driver);
        QVariant varEnable = confSettings.value("Enable");
        QVariant varType = confSettings.value("Type");
        bool enable = (varEnable.isValid() && (varEnable.toString() == "true")) ? true : false;

        QList<int> types;
        QStringList typeStringList;
        if (varType.isValid())
        {
            typeStringList = varType.toStringList();
        }

        Q_FOREACH (auto typeString, typeStringList)
        {
            types << typeString.toInt();
        }
        confSettings.endGroup();

        Q_FOREACH (auto type, types)
        {
            if (type == device_type)
            {
                QJsonObject jsonObj{
                    {"driverName", driver},
                    {"enable", enable}};
                jsonArray.append(jsonObj);
            }
        }
    }
    jsonDoc.setArray(jsonArray);
    return QString(jsonDoc.toJson(QJsonDocument::Compact));
}

void AuthDeviceManager::onRemove(const QDBusMessage& message, const QString& feature_id)
{
    FeatureInfo featureInfo = FeatureDB::getInstance()->getFeatureInfo(feature_id);
    bool result = FeatureDB::getInstance()->deleteFeature(feature_id);
    KLOG_DEBUG() << "deleteFeature:" << feature_id
                 << "exec:" << result;
    auto replyMessage = message.createReply();
    QDBusConnection::systemBus().send(replyMessage);

    if (featureInfo.deviceType == DEVICE_TYPE_UKey)
    {
        AuthDeviceList deviceList = m_deviceMap.values();
        for (auto device : deviceList)
        {
            if (device->deviceType() != DEVICE_TYPE_UKey)
            {
                continue;
            }
            auto ukeyDevice = qobject_cast<UKeySKFDevice*>(device);
            if (ukeyDevice->deviceSerialNumber() != featureInfo.deviceSerialNumber)
            {
                continue;
            }
            ukeyDevice->resetUkey();
        }
    }
}

// TODO:是否需要监听配置文件的改变
void AuthDeviceManager::onSetEnableDriver(const QDBusMessage& message, const QString& driver_name, bool enable)
{
    QStringList driverList = ConfigHelper::getDriverList();
    QDBusMessage replyMessage;

    do
    {
        if (!driverList.contains(driver_name))
        {
            replyMessage = message.createErrorReply(QDBusError::Failed, "No driver with the corresponding name was found.");
            break;
        }
        ConfigHelper::setDriverEnabled(driver_name, enable);
        replyMessage = message.createReply();

        if (enable)
        {
            break;
        }

        // 驱动被禁用，将当前正在使用的设备释放掉
        auto devices = m_deviceMap.values();
        Q_FOREACH (AuthDevicePtr device, devices)
        {
            if (device->driverName() != driver_name)
            {
                continue;
            }
            QString deviceID = device->deviceID();
            int deviceType = device->deviceType();
            device->deleteLater();
            QString key = m_deviceMap.key(device);
            m_deviceMap.remove(key);
            Q_EMIT m_dbusAdaptor->DeviceDeleted(deviceType, deviceID);
            KLOG_INFO() << QString("destroyed deviceType: %1, deviceID:%2").arg(deviceType).arg(deviceID);
        }
    } while (false);

    QDBusConnection::systemBus().send(replyMessage);
}

AuthDeviceList AuthDeviceManager::createDevices(const DeviceInfo& deviceInfo)
{
    // TODO:先从内置默认支持的设备开始搜索，最后才搜索第三方设备
    QString vid = deviceInfo.idVendor;
    QString pid = deviceInfo.idProduct;
    if (!ConfigHelper::isDeviceSupported(vid, pid))
    {
        KLOG_DEBUG() << "no auth device!"
                     << "idVendor:" << vid
                     << "idProduct:" << pid;
        return AuthDeviceList();
    }

    DeviceConf deviceConf = ConfigHelper::getDeviceConf(vid, pid);
    if (!ConfigHelper::driverEnabled(vid, pid))
    {
        KLOG_INFO() << QString("driver:%1 is disabled, auth device: %2 can't be used")
                           .arg(deviceConf.driver)
                           .arg(deviceConf.deviceName)
                    << " vid:" << vid << " pid:" << pid;
        return AuthDeviceList();
    }

    QString libPath = ConfigHelper::getLibPath(vid, pid);
    DriverPtr driverPtr = DriverFactory::getInstance()->getDriver(deviceConf.driver, libPath);

    if (driverPtr.isNull())
    {
        KLOG_ERROR() << QString("get driver: %1 failed!").arg(deviceConf.driver);
        return AuthDeviceList();
    }

    AuthDeviceList deviceList = DeviceCereator::getInstance()->createDevices(vid, pid, driverPtr);
    return deviceList;
}

CHECK_AUTH_WITH_1ARGS(AuthDeviceManager, Remove, onRemove, AUTH_USER_ADMIN, const QString&)
CHECK_AUTH_WITH_2ARGS(AuthDeviceManager, SetEnableDriver, onSetEnableDriver, AUTH_USER_ADMIN, const QString&, bool)

void AuthDeviceManager::init()
{
    m_dbusAdaptor = QSharedPointer<AuthDeviceManagerAdaptor>(new AuthDeviceManagerAdaptor(this));
    m_ReCreateTimer.setInterval(1000);
    connect(&m_ReCreateTimer, &QTimer::timeout, this, &AuthDeviceManager::handleDeviceReCreate);

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

    m_udevMonitor = QSharedPointer<UdevMonitor>(new UdevMonitor());
    connect(m_udevMonitor.data(), &UdevMonitor::deviceAdded, this, &AuthDeviceManager::handleDeviceAdded);
    connect(m_udevMonitor.data(), &UdevMonitor::deviceDeleted, this, &AuthDeviceManager::handleDeviceDeleted);

    auto usbInfoList = Utils::enumerateDevices();
    // 枚举设备后，生成设备对象
    Q_FOREACH (auto deviceInfo, usbInfoList)
    {
        handleDeviceAdded(deviceInfo);
    }
}

void AuthDeviceManager::handleDeviceAdded(const DeviceInfo& deviceInfo)
{
    AuthDeviceList deviceList = createDevices(deviceInfo);
    if (deviceList.count() == 0)
    {
        handleDeviceCreateFail(deviceInfo);
        return;
    }

    Q_FOREACH (auto device, deviceList)
    {
        m_deviceMap.insert(deviceInfo.busPath, device);
        Q_EMIT m_dbusAdaptor->DeviceAdded(device->deviceType(), device->deviceID());

        KLOG_DEBUG() << "auth device added"
                     << "idVendor:" << deviceInfo.idVendor
                     << "idProduct:" << deviceInfo.idProduct
                     << "bus:" << deviceInfo.busPath;
    }
}

void AuthDeviceManager::handleDeviceCreateFail(DeviceInfo deviceInfo)
{
    m_retreyCreateDeviceMap.insert(deviceInfo, 0);
    if (m_retreyCreateDeviceMap.count() != 0)
    {
        if (!m_ReCreateTimer.isActive())
        {
            m_ReCreateTimer.start();
        }
    }
}

void AuthDeviceManager::handleDeviceDeleted()
{
    QList<DeviceInfo> newUsbInfoList = Utils::enumerateDevices();
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
        if (newBusList.contains(busPath))
        {
            continue;
        }

        AuthDevicePtr oldAuthDevice = m_deviceMap.value(busPath);
        deviceID = oldAuthDevice->deviceID();
        deviceType = oldAuthDevice->deviceType();
        int removeCount = m_deviceMap.remove(busPath);

        Q_EMIT m_dbusAdaptor->DeviceDeleted(deviceType, deviceID);

        QMapIterator<DeviceInfo, int> i(m_retreyCreateDeviceMap);
        while (i.hasNext())
        {
            i.next();
            if (i.key().busPath == busPath)
            {
                m_retreyCreateDeviceMap.remove(i.key());
            }
        }
        KLOG_DEBUG() << QString("device delete: bus:%1 deviceID:%2 deviceType:%3").arg(busPath).arg(deviceID).arg(deviceType);
        break;
    }
}

void AuthDeviceManager::handleDeviceReCreate()
{
    if (m_retreyCreateDeviceMap.count() == 0)
    {
        m_ReCreateTimer.stop();
        return;
    }

    QMapIterator<DeviceInfo, int> i(m_retreyCreateDeviceMap);
    while (i.hasNext())
    {
        i.next();
        if (i.value() >= MAX_RETREY_CREATE_COUNT)
        {
            m_retreyCreateDeviceMap.remove(i.key());
            continue;
        }

        auto deviceInfo = i.key();

        AuthDeviceList deviceList = createDevices(deviceInfo);
        if (deviceList.count() == 0)
        {
            m_retreyCreateDeviceMap.insert(i.key(), i.value() + 1);
            continue;
        }

        Q_FOREACH (auto device, deviceList)
        {
            m_deviceMap.insert(deviceInfo.busPath, device);
            Q_EMIT m_dbusAdaptor->DeviceAdded(device->deviceType(), device->deviceID());

            KLOG_DEBUG() << "device added"
                         << "idVendor:" << deviceInfo.idVendor
                         << "idProduct:" << deviceInfo.idProduct
                         << "bus:" << deviceInfo.busPath;
        }

        m_retreyCreateDeviceMap.remove(i.key());
    }
}
}  // namespace Kiran
