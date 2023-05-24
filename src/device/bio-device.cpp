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

#include "bio-device.h"
#include <qt5-log-i.h>
#include <QtConcurrent>
#include "auth_device_adaptor.h"
#include "feature-db.h"

namespace Kiran
{
#define TEMPLATE_MAX_NUMBER 1000

BioDevice::BioDevice(QObject *parent) : AuthDevice{parent},
                                        m_futureWatcher(nullptr)
{
    initFutureWatcher();
}

BioDevice::~BioDevice()
{
}

void BioDevice::doingEnrollStart(const QString &extraInfo)
{
    KLOG_DEBUG() << "biological information enroll start";
    // 获取当前保存的特征模板，判断是否达到最大数目
    QByteArrayList saveList = FeatureDB::getInstance()->getFeatures(deviceInfo().idVendor, deviceInfo().idProduct, deviceType());
    if (saveList.count() == TEMPLATE_MAX_NUMBER)
    {
        QString message = tr("feature has reached the upper limit of %1").arg(TEMPLATE_MAX_NUMBER);
        Q_EMIT m_dbusAdaptor->EnrollStatus("", 0, ENROLL_STATUS_FAIL, message);
        KLOG_ERROR() << message;
        internalStopEnroll();
        return;
    }
    m_doAcquire = true;
    auto future = QtConcurrent::run(this, &BioDevice::acquireFeature);
    m_futureWatcher->setFuture(future);

    QString message;
    switch (deviceType())
    {
    case DEVICE_TYPE_FingerPrint:
        message = tr("Please press your finger");
        break;
    case DEVICE_TYPE_FingerVein:
        message = tr("Please put your finger in");
        break;
    default:
        break;
    }

    m_dbusAdaptor->EnrollStatus("", 0, ENROLL_STATUS_NORMAL, message);
}

void BioDevice::doingIdentifyStart(const QString &value)
{
    KLOG_DEBUG() << "biological information identify start";
    m_doAcquire = true;
    auto future = QtConcurrent::run(this, &BioDevice::acquireFeature);
    m_futureWatcher->setFuture(future);

    QString message;
    switch (deviceType())
    {
    case DEVICE_TYPE_FingerPrint:
        message = tr("Please press your finger");
        break;
    case DEVICE_TYPE_FingerVein:
        message = tr("Please put your finger in");
        break;
    default:
        break;
    }
    m_dbusAdaptor->IdentifyStatus("", ENROLL_STATUS_NORMAL, message);
}

void BioDevice::internalStopEnroll()
{
    if (deviceStatus() == DEVICE_STATUS_DOING_ENROLL)
    {
        acquireFeatureStop();
        m_enrollTemplates.clear();
        setDeviceStatus(DEVICE_STATUS_IDLE);
        clearWatchedServices();
        KLOG_DEBUG() << QString("device type:%1,internal enroll stop").arg(deviceType());
    }
}

void BioDevice::internalStopIdentify()
{
    if (deviceStatus() == DEVICE_STATUS_DOING_IDENTIFY)
    {
        acquireFeatureStop();
        m_identifyIDs.clear();
        setDeviceStatus(DEVICE_STATUS_IDLE);
        clearWatchedServices();
        KLOG_DEBUG() << QString("device type:%1,internal identify stop").arg(deviceType());
    }
}

void BioDevice::doingEnrollProcess(QByteArray feature)
{
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
    else if (templatesCount < mergeTemplateCount())
    {
        // 判断录入时是否录的是同一根手指
        int matchResult = enrollTemplateMatch(m_enrollTemplates.value(0), feature);
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
    else if (enrollTemplatesFromCache().count() == mergeTemplateCount())
    {
        enrollTemplateMerge();
    }
}

void BioDevice::doingIdentifyProcess(QByteArray feature)
{
    QString featureID = identifyFeature(feature, m_identifyIDs);
    if (!featureID.isEmpty())
    {
        notifyIdentifyProcess(IDENTIFY_PROCESS_MACTCH, featureID);
    }
    else
    {
        notifyIdentifyProcess(IDENTIFY_PROCESS_NO_MATCH);
    }

    internalStopIdentify();
}

void BioDevice::handleAcquiredFeature()
{
    auto future = m_futureWatcher->future();
    if (!future.isResultReadyAt(0))
    {
        KLOG_DEBUG() << "acquired feature is not available";
        acquireFeatureFail();
        return;
    }
    QByteArray feature = m_futureWatcher->result();
    if (feature.isEmpty())
    {
        acquireFeatureFail();
        return;
    }

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

QByteArrayList BioDevice::enrollTemplatesFromCache()
{
    return m_enrollTemplates;
}

void BioDevice::saveEnrollTemplateToCache(QByteArray enrollTemplate)
{
    if (!enrollTemplate.isEmpty())
    {
        m_enrollTemplates << enrollTemplate;
        KLOG_DEBUG() << "enroll template:" << enrollTemplate;
        notifyEnrollProcess(ENROLL_PROCESS_PASS);
    }
}

void BioDevice::enrollProcessRetry()
{
    Q_EMIT this->retry();
}

QString BioDevice::isFeatureEnrolled(QByteArray fpTemplate)
{
    return identifyFeature(fpTemplate, QStringList());
}

void BioDevice::initFutureWatcher()
{
    m_futureWatcher = QSharedPointer<QFutureWatcher<QByteArray>>(new QFutureWatcher<QByteArray>(this));
    connect(m_futureWatcher.data(), &QFutureWatcher<QByteArray>::finished, this, &BioDevice::handleAcquiredFeature);
    connect(this, &AuthDevice::retry, this, &BioDevice::handleRetry);
}

void BioDevice::handleRetry()
{
    auto future = QtConcurrent::run(this, &BioDevice::acquireFeature);
    m_futureWatcher->setFuture(future);
}

}  // namespace Kiran