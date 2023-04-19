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

#include "bio-device.h"
#include <qt5-log-i.h>
namespace Kiran
{
BioDevice::BioDevice(QObject *parent) : AuthDevice{parent}
{
}

BioDevice::~BioDevice()
{
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

}  // namespace Kiran