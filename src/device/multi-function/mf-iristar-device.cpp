/**
 * Copyright (c) 2020 ~ 2023 KylinSec Co., Ltd.
 * kiran-authentication-devices is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 * http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 *
 * Author: luoqing <luoqing@kylinsec.com.cn>
 */

#include "mf-iristar-device.h"
#include <qt5-log-i.h>
#include <QMetaType>
#include "auth_device_adaptor.h"

namespace Kiran
{
#define IRIS_IS_DRIVER_LIB "libirs_sdk2.so"

MFIriStarDevice::MFIriStarDevice(DeviceType deviceType, QObject *parent) : AuthDevice(parent)
{
    setDeviceType(deviceType);
    setDeviceDriver(IRIS_IS_DRIVER_LIB);
    m_driver = MFIriStarDriver::getInstance();
    m_driver->ref();

    qRegisterMetaType<EnrollProcess>("EnrollProcess");
    qRegisterMetaType<IdentifyProcess>("IdentifyProcess");
    qRegisterMetaType<DeviceType>("DeviceType");

    connect(m_driver, &MFIriStarDriver::enrollProcess, this, &MFIriStarDevice::onEnrollProcess);
    connect(m_driver, &MFIriStarDriver::identifyProcess, this, &MFIriStarDevice::onIdentifyProcess);
}

MFIriStarDevice::~MFIriStarDevice()
{
    m_driver->unref();
    KLOG_DEBUG() << "refCount:" << m_driver->refCount();
    if(m_driver->refCount() <= 0)
    {
        delete m_driver;
    }
}

bool MFIriStarDevice::initDriver()
{
    if (!m_driver->isInitialized())
    {
        m_driver->initDriver();
    }

    return m_driver->isInitialized();
}

void MFIriStarDevice::doingEnrollStart(const QString &extraInfo)
{
    m_driver->doingEnrollStart(deviceType());
}

void MFIriStarDevice::doingIdentifyStart(const QString &value)
{
    m_driver->doingIdentifyStart(deviceType(), m_identifyIDs);
}

void MFIriStarDevice::internalStopEnroll()
{
    if (deviceStatus() == DEVICE_STATUS_DOING_ENROLL)
    {
        m_driver->stop();
        setDeviceStatus(DEVICE_STATUS_IDLE);
        clearWatchedServices();
        KLOG_DEBUG() << "stop Enroll";
    }
}

void MFIriStarDevice::internalStopIdentify()
{
    if (deviceStatus() == DEVICE_STATUS_DOING_IDENTIFY)
    {
        m_driver->stop();
        m_identifyIDs.clear();
        setDeviceStatus(DEVICE_STATUS_IDLE);
        clearWatchedServices();
        KLOG_DEBUG() << "stop Identify";
    }
}

void MFIriStarDevice::onEnrollProcess(EnrollProcess process, DeviceType type, const QString &featureID)
{
    if (deviceType() != type)
    {
        return;
    }
    notifyEnrollProcess(process, featureID);
    internalStopEnroll();
}
void MFIriStarDevice::onIdentifyProcess(IdentifyProcess process, DeviceType type, const QString &featureID)
{
    if (deviceType() != type)
    {
        return;
    }
    notifyIdentifyProcess(process, featureID);
    internalStopIdentify();
}

void MFIriStarDevice::notifyEnrollProcess(EnrollProcess process, const QString &featureID)
{
    if (deviceStatus() != DEVICE_STATUS_DOING_ENROLL)
    {
        return;
    }
    QString message;
    switch (process)
    {
    case ENROLL_PROCESS_ACQUIRE_FEATURE_FAIL:
        message = tr("feature image not obtained");
        Q_EMIT m_dbusAdaptor->EnrollStatus("", 0, ENROLL_RESULT_RETRY, message);
        break;
    case ENROLL_PROCESS_REPEATED_ENROLL:
        message = tr("The feature has been enrolled");
        Q_EMIT m_dbusAdaptor->EnrollStatus(featureID, 0, ENROLL_RESULT_FAIL, message);
        break;
    case ENROLL_PROCESS_SUCCESS:
        message = tr("Successed save feature");
        Q_EMIT m_dbusAdaptor->EnrollStatus(featureID, 100, ENROLL_RESULT_COMPLETE, message);
        break;
    case ENROLL_PROCESS_SAVE_FAIL:
        message = tr("Save Feature Failed!");
        Q_EMIT m_dbusAdaptor->EnrollStatus("", 0, ENROLL_RESULT_FAIL, message);
        break;
    default:
        break;
    }
    if (!message.isEmpty())
    {
        if (!featureID.isEmpty())
        {
            KLOG_DEBUG() << QString("%1, feature id:%2").arg(message).arg(featureID);
        }
        else
        {
            KLOG_DEBUG() << message;
        }
    }
}

void MFIriStarDevice::notifyIdentifyProcess(IdentifyProcess process, const QString &featureID)
{
    if (deviceStatus() != DEVICE_STATUS_DOING_IDENTIFY)
    {
        return;
    }
    QString message;
    switch (process)
    {
    case IDENTIFY_PROCESS_ACQUIRE_FEATURE_FAIL:
        message = tr("acquire feature fail!");
        Q_EMIT m_dbusAdaptor->IdentifyStatus("", IDENTIFY_RESULT_RETRY, message);
        break;
    case IDENTIFY_PROCESS_MACTCH:
        message = tr("Feature Match");
        Q_EMIT m_dbusAdaptor->IdentifyStatus(featureID, IDENTIFY_RESULT_MATCH, message);
        break;
    case IDENTIFY_PROCESS_NO_MATCH:
        message = tr("Feature not match, place again");
        Q_EMIT m_dbusAdaptor->IdentifyStatus(featureID, IDENTIFY_RESULT_NOT_MATCH, message);
        break;
    default:
        break;
    }
    if (!message.isEmpty())
    {
        if (!featureID.isEmpty())
        {
            KLOG_DEBUG() << QString("%1, feature id:%2").arg(message).arg(featureID);
        }
        else
        {
            KLOG_DEBUG() << message;
        }
    }
}
}  // namespace Kiran
