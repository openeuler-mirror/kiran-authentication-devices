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
#include "context/context-factory.h"
#include "device/auth-device.h"
#include "feature-db.h"
#include "kiran-auth-device-i.h"
#include "polkit-proxy.h"
#include "utils.h"

namespace Kiran
{
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
    QSettings confSettings(DRIVERS_CONF, QSettings::NativeFormat);
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
    bool result = FeatureDB::getInstance()->deleteFeature(feature_id);
    KLOG_DEBUG() << "deleteFeature:" << feature_id
                 << "exec:" << result;
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
        Q_FOREACH (AuthDevicePtr device, devices)
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
    m_dbusAdaptor = QSharedPointer<AuthDeviceManagerAdaptor>(new AuthDeviceManagerAdaptor(this));
    m_contextFactory = QSharedPointer<ContextFactory>(ContextFactory::getInstance());
    connect(&m_timer, &QTimer::timeout, this, &AuthDeviceManager::handleDeviceReCreate);

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
        if (m_contextFactory->isDeviceSupported(deviceInfo.idVendor, deviceInfo.idProduct))
        {
            AuthDeviceList deviceList = m_contextFactory->createDevices(deviceInfo.idVendor, deviceInfo.idProduct);
            if (deviceList.count() != 0)
            {
                Q_FOREACH (auto device, deviceList)
                {
                    m_deviceMap.insert(deviceInfo.busPath, device);
                }
            }
            else
            {
                handleDeviceCreateFail(deviceInfo);
            }
        }
    }
}

void AuthDeviceManager::handleDeviceAdded(const DeviceInfo& deviceInfo)
{
    if (m_contextFactory->isDeviceSupported(deviceInfo.idVendor, deviceInfo.idProduct))
    {
        AuthDeviceList deviceList = m_contextFactory->createDevices(deviceInfo.idVendor, deviceInfo.idProduct);
        if (deviceList.count() != 0)
        {
            Q_FOREACH (auto device, deviceList)
            {
                m_deviceMap.insert(deviceInfo.busPath, device);
                Q_EMIT this->DeviceAdded(device->deviceType(), device->deviceID());
                Q_EMIT m_dbusAdaptor->DeviceAdded(device->deviceType(), device->deviceID());
                KLOG_DEBUG() << "auth device added"
                             << "idVendor:" << deviceInfo.idVendor
                             << "idProduct:" << deviceInfo.idProduct
                             << "bus:" << deviceInfo.busPath;
            }
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
        if (!m_timer.isActive())
        {
            m_timer.start(1000);
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
        if (!newBusList.contains(busPath))
        {
            AuthDevicePtr oldAuthDevice = m_deviceMap.value(busPath);
            deviceID = oldAuthDevice->deviceID();
            deviceType = oldAuthDevice->deviceType();
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
        m_timer.stop();
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
                AuthDeviceList deviceList = m_contextFactory->createDevices(deviceInfo.idVendor, deviceInfo.idProduct);
                if (deviceList.count() != 0)
                {
                    Q_FOREACH (auto device, deviceList)
                    {
                        m_deviceMap.insert(deviceInfo.busPath, device);
                        Q_EMIT this->DeviceAdded(device->deviceType(), device->deviceID());
                        Q_EMIT m_dbusAdaptor->DeviceAdded(device->deviceType(), device->deviceID());

                        KLOG_DEBUG() << "device added"
                                     << "idVendor:" << deviceInfo.idVendor
                                     << "idProduct:" << deviceInfo.idProduct
                                     << "bus:" << deviceInfo.busPath;
                    }

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
