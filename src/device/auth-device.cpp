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
#define TEMPLATE_MAX_NUMBER 1000

size_t AuthDevice::m_deviceObjectNum = 0;

AuthDevice::AuthDevice(QObject* parent) : QObject(parent),
                                          m_dbusAdaptor(nullptr),
                                          m_serviceWatcher(nullptr),
                                          m_futureWatcher(nullptr)
{
}

AuthDevice::~AuthDevice(){};

bool AuthDevice::init()
{
    if (initDevice())
    {
        m_dbusAdaptor = new AuthDeviceAdaptor(this);
        m_deviceID = QUuid::createUuid().toString(QUuid::WithoutBraces);
        m_deviceStatus = DEVICE_STATUS_IDLE;
        registerDBusObject();
        initFutureWatcher();
        initServiceWatcher();
        return true;
    }
    else
        return false;
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
        KLOG_WARNING() << "Can't register object:" << dbusConnection.lastError();
}

void AuthDevice::initFutureWatcher()
{
    m_futureWatcher = new QFutureWatcher<QByteArray>(this);
    connect(m_futureWatcher, &QFutureWatcher<QByteArray>::finished, this, &AuthDevice::handleAcquiredFeature);
    connect(this, &AuthDevice::retry, this, &AuthDevice::handleRetry);
}

void AuthDevice::initServiceWatcher()
{
    m_serviceWatcher = new QDBusServiceWatcher(this);
    this->m_serviceWatcher->setConnection(QDBusConnection::systemBus());
    this->m_serviceWatcher->setWatchMode(QDBusServiceWatcher::WatchForUnregistration);
    connect(m_serviceWatcher, &QDBusServiceWatcher::serviceUnregistered, this, &AuthDevice::onNameLost);
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

void AuthDevice::setDeviceType(DeviceType deviceType)
{
    m_deviceType = deviceType;
}

void AuthDevice::setDeviceStatus(DeviceStatus deviceStatus)
{
    m_deviceStatus = deviceStatus;
}

void AuthDevice::setDeviceName(const QString& deviceName)
{
    m_deviceName = deviceName;
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
        driverName = deviceDriver;
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

    // 获取当前保存的指纹模板，判断是否达到最大指纹数目
    QByteArrayList saveList = FeatureDB::getInstance()->getFeatures(m_idVendor, m_idProduct);
    if (saveList.count() == TEMPLATE_MAX_NUMBER)
    {
        message = tr("feature has reached the upper limit of %1").arg(TEMPLATE_MAX_NUMBER);
        Q_EMIT m_dbusAdaptor->EnrollStatus("", 0, ENROLL_RESULT_FAIL, message);
        KLOG_ERROR() << message;
        return;
    }

    setDeviceStatus(DEVICE_STATUS_DOING_ENROLL);
    m_doEnroll = true;

    auto future = QtConcurrent::run(this, &AuthDevice::acquireFeature);
    m_futureWatcher->setFuture(future);
    m_serviceWatcher->addWatchedService(dbusMessage.service());

    auto replyMessage = dbusMessage.createReply();
    QDBusConnection::systemBus().send(replyMessage);
}

void AuthDevice::onEnrollStop(const QDBusMessage& dbusMessage)
{
    if (deviceStatus() == DEVICE_STATUS_DOING_ENROLL)
    {
        acquireFeatureStop();
        m_doEnroll = false;
        m_enrollTemplates.clear();
        setDeviceStatus(DEVICE_STATUS_IDLE);
        clearWatchedServices();
        KLOG_DEBUG() << "EnrollStop";
    }

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

    setDeviceStatus(DEVICE_STATUS_DOING_IDENTIFY);
    m_doIdentify = true;

    QJsonArray jsonArray = Utils::getValueFromJsonString(value, "feature_ids").toArray();
    if (!jsonArray.isEmpty())
    {
        QVariantList varList = jsonArray.toVariantList();
        Q_FOREACH (auto var, varList)
        {
            m_identifyIDs << var.toString();
        }
    }
    auto future = QtConcurrent::run(this, &AuthDevice::acquireFeature);
    m_futureWatcher->setFuture(future);
    m_serviceWatcher->addWatchedService(dbusMessage.service());

    auto replyMessage = dbusMessage.createReply();
    QDBusConnection::systemBus().send(replyMessage);
}

void AuthDevice::onIdentifyStop(const QDBusMessage& message)
{
    if (deviceStatus() == DEVICE_STATUS_DOING_IDENTIFY)
    {
        acquireFeatureStop();
        m_doIdentify = false;
        m_identifyIDs.clear();
        setDeviceStatus(DEVICE_STATUS_IDLE);
        clearWatchedServices();
        KLOG_DEBUG() << "identify stop";
    }
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

void AuthDevice::doingEnrollProcess(QByteArray feature)
{
    if (!m_doEnroll)
    {
        return;
    }
    QString message;
    if (feature.isEmpty())
    {
        acquireFeatureFail();
        return;
    }

    int templatesCount = enrollTemplatesFromCache().count();
    if (templatesCount == 0)
    {
        // 第一个指纹模板入录时，检查该指纹是否录入过
        QString featureID = isFeatureEnrolled(feature);
        if (featureID.isEmpty())
        {
            saveEnrollTemplateToCache(feature);
            enrollProcessRetry();
        }
        else
        {
            notifyEnrollProcess(ENROLL_PROCESS_REPEATED_ENROLL, featureID);
            internalStopEnroll();
        }
    }
    else if (templatesCount < needTemplatesCountForEnroll())
    {
        // 判断录入时是否录的是同一根手指
        int matchResult = templateMatch(m_enrollTemplates.value(0), feature);
        if (matchResult == GENERAL_RESULT_OK)
        {
            saveEnrollTemplateToCache(feature);
        }
        else
        {
            notifyEnrollProcess(ENROLL_PROCESS_INCONSISTENT_FEATURE);
        }
        enrollProcessRetry();
    }
    else if (enrollTemplatesFromCache().count() == needTemplatesCountForEnroll())
    {
        enrollTemplateMerge();
    }
}

void AuthDevice::doingIdentifyProcess(QByteArray feature)
{
    if (!m_doIdentify)
    {
        KLOG_DEBUG() << "device busy";
        return;
    }
    if (feature.isEmpty())
    {
        acquireFeatureFail();
        return;
    }

    QString featureID = identifyFeature(feature, m_identifyIDs);
    if (!featureID.isEmpty())
    {
        notifyIdentifyProcess(IDENTIFY_PROCESS_MACTCH,featureID);
    }
    else
    {
        notifyIdentifyProcess(IDENTIFY_PROCESS_NO_MATCH);
    }

    internalStopIdentify();
}

void AuthDevice::internalStopEnroll()
{
    if (deviceStatus() == DEVICE_STATUS_DOING_ENROLL)
    {
        acquireFeatureStop();
        m_doEnroll = false;
        m_enrollTemplates.clear();
        setDeviceStatus(DEVICE_STATUS_IDLE);
        clearWatchedServices();
        KLOG_DEBUG() << "internalStopEnroll";
    }
}

void AuthDevice::internalStopIdentify()
{
    if (deviceStatus() == DEVICE_STATUS_DOING_IDENTIFY)
    {
        acquireFeatureStop();
        m_doIdentify = false;
        m_identifyIDs.clear();
        setDeviceStatus(DEVICE_STATUS_IDLE);
        clearWatchedServices();
        KLOG_DEBUG() << "identify stop";
    }
}

void AuthDevice::enrollProcessRetry()
{
    Q_EMIT this->retry();
}

void AuthDevice::saveEnrollTemplateToCache(QByteArray enrollTemplate)
{
    if (!enrollTemplate.isEmpty())
    {
        m_enrollTemplates << enrollTemplate;
        KLOG_DEBUG() << "enroll template:" << enrollTemplate;
        notifyEnrollProcess(ENROLL_PROCESS_PASS);
    }
}

QByteArrayList AuthDevice::enrollTemplatesFromCache()
{
    return m_enrollTemplates;
}

void AuthDevice::handleAcquiredFeature()
{
    switch (deviceStatus())
    {
    case DEVICE_STATUS_DOING_ENROLL:
        doingEnrollProcess(m_futureWatcher->result());
        break;
    case DEVICE_STATUS_DOING_IDENTIFY:
        doingIdentifyProcess(m_futureWatcher->result());
        break;
    default:
        break;
    }
}

void AuthDevice::handleRetry()
{
    auto future = QtConcurrent::run(this, &AuthDevice::acquireFeature);
    m_futureWatcher->setFuture(future);
}

}  // namespace Kiran