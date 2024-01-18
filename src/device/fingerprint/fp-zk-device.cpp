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

#include "fp-zk-device.h"
#include <dlfcn.h>
#include <qt5-log-i.h>
#include <sys/time.h>
#include <unistd.h>
#include <QByteArray>
#include <QCryptographicHash>
#include <QDataStream>
#include <QDir>
#include <QJsonValue>
#include "auth_device_adaptor.h"
#include "device/device-creator.h"
#include "driver/fingerprint/fp-zk-driver.h"
#include "zkfp.h"
#include <QFuture>
#include <QtConcurrent>
#include "feature-db.h"
#include "utils.h"

namespace Kiran
{

REGISTER_DEVICE(FINGERPRINT_ZK_DRIVER_NAME, FPZKDevice);

FPZKDevice::FPZKDevice(const QString& vid, const QString& pid, DriverPtr driver, QObject* parent)
    : BioDevice{vid, pid, driver, parent},
      m_hDBCache(nullptr)
{
    setDeviceType(DEVICE_TYPE_FingerPrint);
    setDriverName(FINGERPRINT_ZK_DRIVER_NAME);
    setMergeTemplateCount(FP_ZK_MEGER_TEMPLATE_COUNT);
    m_driver = driver.dynamicCast<FPZKDriver>();
}

// 析构时对设备进行资源回收
FPZKDevice::~FPZKDevice()
{
    KLOG_DEBUG() << "destroy FPZK Device";
    acquireFeatureStop();

    if (m_driver->isLoaded())
    {
        if (m_hDBCache)
        {
            m_driver->ZKFPM_DBFree(m_hDBCache);
            m_hDBCache = NULL;
        }
        m_driver->ZKFPM_Terminate();  // 释放资源
    }
}

bool FPZKDevice::initDevice()
{
    int ret = m_driver->ZKFPM_Init();
    if (ret != ZKFP_ERR_OK)
    {
        return false;
    }

    m_hDBCache = m_driver->ZKFPM_DBInit();  // 创建算法缓冲区   返回值：缓冲区句柄
    if (NULL == m_hDBCache)
    {
        return false;
    }

    return true;
}

Handle FPZKDevice::openDevice()
{
    int devCount = getDevCount();
    if (devCount <= 0)
    {
        // 没有插入设备
        KLOG_ERROR() << "No Found Device";
        return nullptr;
    }

    // FIXME:无法在硬件层面区分两个相同的ZK设备，试试通过接口ZKFPM_GetParameters 获取序列号，能否区分
    Handle hDevice = nullptr;
    for (int i = 0; i < devCount; i++)
    {
        //  默认打开一个设备
        hDevice = m_driver->ZKFPM_OpenDevice(i);
        if (hDevice)
            break;
    }
    return hDevice;
}

QByteArray FPZKDevice::acquireFeature()
{
    KLOG_DEBUG() << "start acquire feature";
    Handle hDevice = openDevice();
    if (!hDevice)
    {
        KLOG_ERROR() << "Open Device Fail! id:" << deviceID();
        return QByteArray();
    }

    QByteArray fpTemplate;
    char paramValue[4] = {0x0};
    unsigned int cbParamValue = 4;
    int imageBufferSize = 0;
    unsigned char* pImgBuf = NULL;
    unsigned char szTemplate[FP_ZK_MAX_TEMPLATE_SIZE];
    unsigned int tempLen = FP_ZK_MAX_TEMPLATE_SIZE;
    unsigned int curTime;
    int ret;

    memset(paramValue, 0x0, 4);  // 初始化paramValue[4]
    cbParamValue = 4;            // 初始化cbParamValue
    /* |   设备  |   参数类型     |  参数值     |  参数数据长度  */
    m_driver->ZKFPM_GetParameters(hDevice, 1, (unsigned char*)paramValue, &cbParamValue);  // 获取采集器参数 图像宽

    memset(paramValue, 0x0, 4);                                                            // 初始化paramValue[4]
    cbParamValue = 4;                                                                      // 初始化cbParamValue
    /* |   设备  |   参数类型     |  参数值     |  参数数据长度  */
    m_driver->ZKFPM_GetParameters(hDevice, 2, (unsigned char*)paramValue, &cbParamValue);  // 获取采集器参数 图像高

    memset(paramValue, 0x0, 4);                                                            // 初始化paramValue[4]
    cbParamValue = 4;                                                                      // 初始化cbParamValue
    /* |   设备  |   参数类型     |  参数值     |  参数数据长度  */
    m_driver->ZKFPM_GetParameters(hDevice, 106, (unsigned char*)paramValue, &cbParamValue);  // 获取采集器参数 图像数据大小

    imageBufferSize = *((int*)paramValue);
    pImgBuf = (unsigned char*)malloc(imageBufferSize);
    if (pImgBuf == NULL)
    {
        m_driver->ZKFPM_CloseDevice(hDevice);
        return QByteArray();
    }

    ret = GENERAL_RESULT_FAIL;

    while (m_doAcquire)
    {
        ret = m_driver->ZKFPM_AcquireFingerprint(hDevice,
                                                 pImgBuf, imageBufferSize,
                                                 szTemplate, &tempLen);
        if (ret == GENERAL_RESULT_OK)
        {
            KLOG_DEBUG() << "acquire fingerprint success";
            break;
        }
        else if (ret == ZKFP_ERR_EXTRACT_FP ||
                 ret == ZKFP_ERR_ABSORT ||
                 ret == ZKFP_ERR_FAIL ||
                 ret == ZKFP_ERR_TIMEOUT)
        {
            KLOG_DEBUG() << "acquire fingerprint fail! ZKFP_ERR:" << ret;
            break;
        }
    }

    if (ret == GENERAL_RESULT_OK)
    {
        fpTemplate = QByteArray((char*)szTemplate, tempLen);
    }

    free(pImgBuf);
    pImgBuf = NULL;

    m_driver->ZKFPM_CloseDevice(hDevice);

    return fpTemplate;
}

void FPZKDevice::acquireFeatureStop()
{
    m_doAcquire = false;
    if (!m_futureWatcher.isNull())
    {
        m_futureWatcher->waitForFinished();
    }
}

void FPZKDevice::acquireFeatureFail()
{
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

QByteArray FPZKDevice::templateMerge(QByteArray fpTemplate1,
                                     QByteArray fpTemplate2,
                                     QByteArray fpTemplate3)
{
    unsigned int cbRegTemp = FP_ZK_MAX_TEMPLATE_SIZE;
    QByteArray regTemplate;
    regTemplate.resize(FP_ZK_MAX_TEMPLATE_SIZE);
    regTemplate.fill(0);
    int ret = m_driver->ZKFPM_DBMerge(m_hDBCache,
                                      reinterpret_cast<unsigned char*>(fpTemplate1.data()),
                                      reinterpret_cast<unsigned char*>(fpTemplate2.data()),
                                      reinterpret_cast<unsigned char*>(fpTemplate3.data()),
                                      reinterpret_cast<unsigned char*>(regTemplate.data()), &cbRegTemp);

    if (ret != GENERAL_RESULT_OK)
        return QByteArray();

    regTemplate.resize(cbRegTemp);
    return regTemplate;
}

int FPZKDevice::enrollTemplateMatch(QByteArray fpTemplate1, QByteArray fpTemplate2)
{
    int score = 0;
    score = m_driver->ZKFPM_DBMatch(m_hDBCache,
                                    (unsigned char*)fpTemplate1.data(), fpTemplate1.size(),
                                    (unsigned char*)fpTemplate2.data(), fpTemplate2.size());

    return score > 0 ? GENERAL_RESULT_OK : GENERAL_RESULT_FAIL;
}

QString FPZKDevice::identifyFeature(QByteArray fpTemplate, QList<QByteArray> existedfeatures)
{
    QString featureID;
    for (int j = 0; j < existedfeatures.count(); j++)
    {
        auto saveTemplate = existedfeatures.value(j);
        int ret = enrollTemplateMatch(fpTemplate, saveTemplate);
        // 指纹已经存在，直接返回该指纹
        if (ret == GENERAL_RESULT_OK)
        {
            featureID = FeatureDB::getInstance()->getFeatureID(saveTemplate);
            break;
        }
    }

    return featureID;
}

bool FPZKDevice::saveFPrintTemplate(QByteArray fpTemplate, const QString& featureID)
{
    DeviceInfo deviceInfo = this->deviceInfo();
    bool save = FeatureDB::getInstance()->addFeature(featureID, fpTemplate, deviceInfo, deviceType());
    return save;
}

int FPZKDevice::getDevCount()
{
    return m_driver->ZKFPM_GetDeviceCount();
}

void FPZKDevice::enrollTemplateMerge()
{
    QString message;
    // 将三个模板merge
    QByteArray regTemplate = templateMerge(m_enrollTemplates.value(0), m_enrollTemplates.value(1), m_enrollTemplates.value(2));
    if (regTemplate.isEmpty())
    {
        // 三个模板merge失败，判定为录入失败，需要重新录入
        notifyEnrollProcess(ENROLL_PROCESS_MEGER_FAIL);
        return;
    }

    // 合成后的指纹与先前录入的指纹进行匹配
    int matchResult = enrollTemplateMatch(m_enrollTemplates.value(0), regTemplate);
    if (matchResult == GENERAL_RESULT_OK)
    {
        QString featureID = QCryptographicHash::hash(regTemplate, QCryptographicHash::Md5).toHex();
        // 该指纹没有录入过,进行指纹保存
        if (saveFPrintTemplate(regTemplate, featureID))
        {
            notifyEnrollProcess(ENROLL_PROCESS_SUCCESS, featureID);
        }
        else
        {
            notifyEnrollProcess(ENROLL_PROCESS_SAVE_FAIL);
        }
    }
    else
    {
        // 如果合成后的指纹与先前录入的指纹不匹配,判定为录入失败，需要重新录入
        notifyEnrollProcess(ENROLL_PROCESS_INCONSISTENT_FEATURE_AFTER_MERGED);
    }
}

void FPZKDevice::notifyEnrollProcess(EnrollProcess process, const QString& featureID)
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
        Q_EMIT m_dbusAdaptor->EnrollStatus("", enrollTemplatesFromCache().count() * 25, ENROLL_STATUS_PASS, message);
        break;
    case ENROLL_PROCESS_REPEATED_ENROLL:
        message = tr("The fingerprint has been enrolled");
        Q_EMIT m_dbusAdaptor->EnrollStatus(featureID, 0, ENROLL_STATUS_FAIL, message);
        break;
    case ENROLL_PROCESS_INCONSISTENT_FEATURE:
        message = tr("Please place the same finger!");
        KLOG_DEBUG() << message;
        Q_EMIT m_dbusAdaptor->EnrollStatus("", enrollTemplatesFromCache().count() * 25, ENROLL_STATUS_RETRY, message);
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

void FPZKDevice::notifyIdentifyProcess(IdentifyProcess process, const QString& featureID)
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

}  // namespace Kiran
