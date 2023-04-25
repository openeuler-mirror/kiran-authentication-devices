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

#include "auth-device.h"
#include <qt5-log-i.h>
#include <QDBusConnection>
#include <QUuid>
#include <QtConcurrent>
#include "auth_device_adaptor.h"
#include "feature-db.h"
#include "kiran-auth-device-i.h"
#include "polkit-proxy.h"
#include "utils.h"

namespace Kiran
{
size_t AuthDevice::m_deviceObjectNum = 0;

AuthDevice::AuthDevice(QObject* parent) : QObject(parent)
{
}

AuthDevice::~AuthDevice(){};

bool AuthDevice::init()
{
    if (!initDevice())
    {
        return false;
    }
    m_dbusAdaptor = QSharedPointer<AuthDeviceAdaptor>(new AuthDeviceAdaptor(this));
    m_deviceID = QUuid::createUuid().toString(QUuid::WithoutBraces);
    m_deviceStatus = DEVICE_STATUS_IDLE;
    registerDBusObject();
    initServiceWatcher();
    return true;
}

void AuthDevice::registerDBusObject()
{
    m_deviceObjectNum += 1;
    m_objectPath = QDBusObjectPath(QString("%1%2").arg(GENERAL_AUTH_DEVICE_DBUS_OBJECT_PATH).arg(m_deviceObjectNum));
    QDBusConnection dbusConnection = QDBusConnection::systemBus();
    if (dbusConnection.registerObject(m_objectPath.path(),
                                      GENERAL_AUTH_DEVICE_DBUS_INTERFACE_NAME,
                                      this))
    {
        KLOG_DEBUG() << "register Object :" << m_objectPath.path();
    }
    else
    {
        KLOG_WARNING() << "Can't register object:" << dbusConnection.lastError();
    }
}

void AuthDevice::initServiceWatcher()
{
    m_serviceWatcher = QSharedPointer<QDBusServiceWatcher>(new QDBusServiceWatcher(this));
    this->m_serviceWatcher->setConnection(QDBusConnection::systemBus());
    this->m_serviceWatcher->setWatchMode(QDBusServiceWatcher::WatchForUnregistration);
    connect(m_serviceWatcher.data(), &QDBusServiceWatcher::serviceUnregistered, this, &AuthDevice::onNameLost);
}

void AuthDevice::onNameLost(const QString& serviceName)
{
    KLOG_DEBUG() << "NameLost: " << serviceName;
    this->m_serviceWatcher->removeWatchedService(serviceName);
    switch (deviceStatus())
    {
    case DEVICE_STATUS_DOING_ENROLL:
        internalStopEnroll();
        break;
    case DEVICE_STATUS_DOING_IDENTIFY:
        internalStopIdentify();
        break;
    default:
        break;
    }
}

void AuthDevice::clearWatchedServices()
{
    QStringList watchedServices = m_serviceWatcher->watchedServices();
    Q_FOREACH (auto service, watchedServices)
    {
        m_serviceWatcher->removeWatchedService(service);
    }
}

DeviceInfo AuthDevice::deviceInfo()
{
    DeviceInfo deviceInfo;
    deviceInfo.idVendor = m_idVendor;
    deviceInfo.idProduct = m_idProduct;
    deviceInfo.busPath = "";
    return deviceInfo;
}

void AuthDevice::setDeviceInfo(const QString& idVendor, const QString& idProduct)
{
    m_idVendor = idVendor;
    m_idProduct = idProduct;
}

void AuthDevice::setDeviceDriver(const QString& deviceDriver)
{
    QString driverName;
    if (deviceDriver.startsWith("lib"))
    {
        driverName = deviceDriver.mid(3, deviceDriver.indexOf(".so") - 3);
    }
    else
    {
        driverName = deviceDriver;
    }
    m_deviceDriver = driverName;
}

void AuthDevice::onEnrollStart(const QDBusMessage& dbusMessage, const QString& extraInfo)
{
    QString message;
    if (deviceStatus() != DEVICE_STATUS_IDLE)
    {
        message = tr("Device Busy");
        Q_EMIT m_dbusAdaptor->EnrollStatus("", 0, ENROLL_RESULT_FAIL, message);
        KLOG_DEBUG() << message;
        return;
    }

    setDeviceStatus(DEVICE_STATUS_DOING_ENROLL);
    m_serviceWatcher->addWatchedService(dbusMessage.service());
    auto replyMessage = dbusMessage.createReply();
    QDBusConnection::systemBus().send(replyMessage);
    doingEnrollStart(extraInfo);
}

void AuthDevice::onEnrollStop(const QDBusMessage& dbusMessage)
{
    internalStopEnroll();
    auto replyMessage = dbusMessage.createReply();
    QDBusConnection::systemBus().send(replyMessage);
}

void AuthDevice::onIdentifyStart(const QDBusMessage& dbusMessage, const QString& value)
{
    QString message;
    if (deviceStatus() != DEVICE_STATUS_IDLE)
    {
        message = tr("Device Busy");
        Q_EMIT m_dbusAdaptor->IdentifyStatus("", IDENTIFY_RESULT_NOT_MATCH, message);
        KLOG_DEBUG() << QString("%1, deviceID:%2").arg(message).arg(deviceID());
        return;
    }

    QJsonArray jsonArray = Utils::getValueFromJsonString(value, AUTH_DEVICE_JSON_KEY_FEATURE_IDS).toArray();
    if (!jsonArray.isEmpty())
    {
        QVariantList varList = jsonArray.toVariantList();
        Q_FOREACH (auto var, varList)
        {
            m_identifyIDs << var.toString();
        }
    }

    setDeviceStatus(DEVICE_STATUS_DOING_IDENTIFY);
    m_serviceWatcher->addWatchedService(dbusMessage.service());
    auto replyMessage = dbusMessage.createReply();
    QDBusConnection::systemBus().send(replyMessage);
    doingIdentifyStart(value);
}

void AuthDevice::onIdentifyStop(const QDBusMessage& message)
{
    internalStopIdentify();
    auto replyMessage = message.createReply();
    QDBusConnection::systemBus().send(replyMessage);
}

CHECK_AUTH_WITH_1ARGS(AuthDevice, EnrollStart, onEnrollStart, AUTH_USER_ADMIN, const QString&)
CHECK_AUTH_WITH_1ARGS(AuthDevice, IdentifyStart, onIdentifyStart, AUTH_USER_ADMIN, const QString&)
CHECK_AUTH(AuthDevice, EnrollStop, onEnrollStop, AUTH_USER_ADMIN)
CHECK_AUTH(AuthDevice, IdentifyStop, onIdentifyStop, AUTH_USER_ADMIN)

QStringList AuthDevice::GetFeatureIDList()
{
    QStringList featureIDs = FeatureDB::getInstance()->getFeatureIDs(m_idVendor, m_idProduct);
    return featureIDs;
}

}  // namespace Kiran