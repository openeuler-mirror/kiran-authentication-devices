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

#include "fp-za-device.h"
#include <dlfcn.h>
#include <qt5-log-i.h>
#include <sys/time.h>
#include <unistd.h>
#include <QByteArray>
#include <QCryptographicHash>
#include <QDataStream>
#include <QDir>
#include <QFuture>
#include <QJsonValue>
#include <QtConcurrent>
#include "SYProtocol.h"
#include "auth_device_adaptor.h"
#include "device/device-creator.h"
#include "driver/fingerprint/fp-za-driver.h"
#include "feature-db.h"
#include "utils.h"

namespace Kiran
{

REGISTER_DEVICE(FINGERPRINT_ZA_DRIVER_NAME, FPZADevice);

FPZADevice::FPZADevice(const QString& vid, const QString& pid, DriverPtr driver, QObject* parent)
    : BioDevice{vid, pid, driver, parent}
{
    setDeviceType(DEVICE_TYPE_FingerPrint);
    setDriverName(FINGERPRINT_ZA_DRIVER_NAME);
    setMergeTemplateCount(FP_ZA_MEGER_TEMPLATE_COUNT);
    m_driver = driver.dynamicCast<FPZADriver>();
}

// 析构时对设备进行资源回收
FPZADevice::~FPZADevice()
{
    KLOG_DEBUG() << "destroy FPZA Device";
    if (m_driver->isLoaded())
    {
        m_driver->closeDevice();
    }
}

bool FPZADevice::initDevice()
{
    return true;
}

/**
 * 该ZhiAng指纹设备，生成的特征数据是存在buffer1和buffer2两个缓存区
 */
QByteArray FPZADevice::acquireFeature()
{
    int ret = 0;
    QByteArray feature;
    // buffer ID 只能是1或者2,代表两个缓冲区
    int bufferID = (enrollTemplatesFromCache().count() == 0) ? 1 : 2;

    ret = m_driver->acquireFeature(bufferID, feature);
    if (ret != ZAZ_OK)
    {
        return QByteArray();
    }

    return feature;
}

void FPZADevice::acquireFeatureStop()
{
    m_driver->closeDevice();
}

void FPZADevice::acquireFeatureFail()
{
    KLOG_DEBUG() << "acquire Feature Fail";
    if (deviceStatus() == DEVICE_STATUS_DOING_ENROLL)
    {
        notifyEnrollProcess(ENROLL_PROCESS_ACQUIRE_FEATURE_FAIL);
        internalStopEnroll();
    }
    else if (deviceStatus() == DEVICE_STATUS_DOING_IDENTIFY)
    {
        notifyIdentifyProcess(IDENTIFY_PROCESS_ACQUIRE_FEATURE_FAIL);
        internalStopIdentify();
    }
}

void FPZADevice::templateMerge()
{
    KLOG_DEBUG() << "start enroll template merge";
    QByteArray mergedTemplate;
    int ret = m_driver->templateMerge(mergedTemplate);
    if (ret != ZAZ_OK || mergedTemplate.isEmpty())
    {
        // 合成模板失败，判定为录入失败，需要重新录入
        notifyEnrollProcess(ENROLL_PROCESS_MEGER_FAIL);
        return;
    }

    QString featureID = QCryptographicHash::hash(mergedTemplate, QCryptographicHash::Md5).toHex();
    if (saveTemplate(mergedTemplate, featureID))
    {
        notifyEnrollProcess(ENROLL_PROCESS_SUCCESS, featureID);
    }
    else
    {
        notifyEnrollProcess(ENROLL_PROCESS_SAVE_FAIL);
    }
}

// TODO:优化
void FPZADevice::notifyEnrollProcess(EnrollProcess process, const QString& featureID)
{
    QString message;
    switch (process)
    {
    case ENROLL_PROCESS_ACQUIRE_FEATURE_FAIL:
        message = tr("acquire fingerprint fail!");
        Q_EMIT m_dbusAdaptor->EnrollStatus("", 0, ENROLL_STATUS_FAIL, message);
        break;
    case ENROLL_PROCESS_PASS:
        message = tr("Partial fingerprint feature entry,please continue to press your fingers");
        Q_EMIT m_dbusAdaptor->EnrollStatus("", enrollTemplatesFromCache().count() * 33, ENROLL_STATUS_PASS, message);
        break;
    case ENROLL_PROCESS_REPEATED_ENROLL:
        message = tr("The fingerprint has been enrolled");
        Q_EMIT m_dbusAdaptor->EnrollStatus(featureID, 0, ENROLL_STATUS_FAIL, message);
        break;
    case ENROLL_PROCESS_INCONSISTENT_FEATURE:
        message = tr("Please place the same finger!");
        KLOG_DEBUG() << message;
        Q_EMIT m_dbusAdaptor->EnrollStatus("", enrollTemplatesFromCache().count() * 33, ENROLL_STATUS_RETRY, message);
        break;
    case ENROLL_PROCESS_MEGER_FAIL:
        message = tr("Failed to enroll fingerprint, please enroll again");
        Q_EMIT m_dbusAdaptor->EnrollStatus("", 0, ENROLL_STATUS_FAIL, message);
        break;
    case ENROLL_PROCESS_SUCCESS:
        message = tr("Successed save finger");
        Q_EMIT m_dbusAdaptor->EnrollStatus(featureID, 100, ENROLL_STATUS_COMPLETE, message);
        break;
    case ENROLL_PROCESS_SAVE_FAIL:
        message = tr("Save Finger Failed!");
        Q_EMIT m_dbusAdaptor->EnrollStatus("", 0, ENROLL_STATUS_FAIL, message);
        break;
    case ENROLL_PROCESS_INCONSISTENT_FEATURE_AFTER_MERGED:
        message = tr("Failed to enroll fingerprint, please enroll again");
        Q_EMIT m_dbusAdaptor->EnrollStatus("", 0, ENROLL_STATUS_FAIL, message);
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

// TODO:优化
void FPZADevice::notifyIdentifyProcess(IdentifyProcess process, const QString& featureID)
{
    QString message;
    switch (process)
    {
    case IDENTIFY_PROCESS_TIME_OUT:
        break;
    case IDENTIFY_PROCESS_ACQUIRE_FEATURE_FAIL:
        message = tr("acquire fingerprint fail!");
        Q_EMIT m_dbusAdaptor->IdentifyStatus("", IDENTIFY_STATUS_NOT_MATCH, message);
        break;
    case IDENTIFY_PROCESS_MACTCH:
        message = tr("Fingerprint match");
        Q_EMIT m_dbusAdaptor->IdentifyStatus(featureID, IDENTIFY_STATUS_MATCH, message);
        break;
    case IDENTIFY_PROCESS_NO_MATCH:
        message = tr("Fingerprint not match, place again");
        Q_EMIT m_dbusAdaptor->IdentifyStatus(featureID, IDENTIFY_STATUS_NOT_MATCH, message);
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

int FPZADevice::templateMatch(QByteArray fpTemplate1, QByteArray fpTemplate2)
{
    int score = m_driver->matchFeature(fpTemplate1, fpTemplate2);

    return score >= 50 ? GENERAL_RESULT_OK : GENERAL_RESULT_FAIL;
}

QString FPZADevice::identifyFeature(QByteArray fpTemplate, QList<QByteArray> existedfeatures)
{
    QString featureID;
    for (int j = 0; j < existedfeatures.count(); j++)
    {
        auto saveTemplate = existedfeatures.value(j);
        int ret = templateMatch(fpTemplate, saveTemplate);
        if (ret == GENERAL_RESULT_OK)
        {
            featureID = FeatureDB::getInstance()->getFeatureID(saveTemplate);
            break;
        }
    }
    return featureID;
}

int FPZADevice::openBioDevice()
{
    int ret = 0;
    ret = m_driver->openDevice();
    if (ret != ZAZ_OK)
    {
        KLOG_ERROR() << "open device Fail! id:" << deviceID();
        return GENERAL_RESULT_OPEN_DEVICE_FAIL;
    }
    return GENERAL_RESULT_OK;
}

}  // namespace Kiran
