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

#include "fv-sd-device.h"
#include <dlfcn.h>
#include <qt5-log-i.h>
#include <unistd.h>
#include <QFuture>
#include <QtConcurrent>
#include "auth-enum.h"
#include "auth_device_adaptor.h"
#include "device/device-creator.h"
#include "driver/finger-vein/fv-sd-driver.h"
#include "feature-db.h"
#include "sdfv.h"
#include "utils.h"

namespace Kiran
{

REGISTER_DEVICE(FINGER_VEIN_SD_DRIVER_NAME, FVSDDevice);

FVSDDevice::FVSDDevice(const QString &vid, const QString &pid, DriverPtr driver, QObject *parent) : BioDevice{vid, pid, driver, parent}
{
    setDeviceType(DEVICE_TYPE_FingerVein);
    setDriverName(FINGER_VEIN_SD_DRIVER_NAME);
    setMergeTemplateCount(TEMPLATE_FV_NUM);

    m_driver = driver.dynamicCast<FVSDDriver>();
}

FVSDDevice::~FVSDDevice()
{
    KLOG_DEBUG() << "destroy FVSD Device";
    if (m_driver->isLoaded())
    {
        acquireFeatureStop();
        m_driver->TGCloseDev();
    }
}

bool FVSDDevice::initDevice()
{
    int ret = -1;
    int mode = 0;
    char fw[32] = {0};
    char sn[32] = {0};
    // 初始化算法
    ret = m_driver->TGInitFVProcess(SD_LICENSE_PATH);
    if (ret != GENERAL_RESULT_OK)
    {
        KLOG_DEBUG() << "Initialization algorithm failed:" << ret;
        return false;
    }
    KLOG_DEBUG() << "Initialization algorithm succeeded";
    // 打开设备
    ret = m_driver->TGOpenDev(&mode);
    if (ret != GENERAL_RESULT_OK)
    {
        KLOG_DEBUG() << "Failed to open device:" << ret;
        return false;
    }

    KLOG_DEBUG() << "TGGetDevStatus():" << m_driver->TGGetDevStatus();
    if (m_driver->TGGetDevStatus() < 0)
    {
        KLOG_DEBUG() << "device not connected";
        return false;
    }
    KLOG_DEBUG() << "Device opened successfully:" << ret;

    m_driver->TGGetDevFW(fw);
    KLOG_DEBUG() << "Get firmware version:" << fw;
    m_driver->TGGetDevSN(sn);
    KLOG_DEBUG() << "Obtain device SN number:" << sn;
    m_driver->TGPlayDevVoice(VOICE_VOLUME1);

    return true;
}

QByteArray FVSDDevice::acquireFeature()
{
    unsigned char img[IMAGE_SIZE] = {0};   // 指静脉图像(建议保存存储)
    unsigned char fs[FEATURE_SIZE] = {0};  // 指静脉特征

    if (deviceStatus() == DEVICE_STATUS_DOING_ENROLL)
    {
        int voice = (0 == m_enrollTemplates.count()) ? VOICE_PLS_PUT_SOFTLY : VOICE_PLS_REPUT;
        m_driver->TGPlayDevVoice(voice);
    }
    else
    {
        m_driver->TGPlayDevVoice(VOICE_PLS_PUT_SOFTLY);
    }

    // 采集指静脉图像
    int ret = m_driver->TGGetDevImage(img, IMAGE_TIME_OUT);
    KLOG_DEBUG() << "Collecting digital vein images:" << ret;
    if (ret == -1)
    {
        KLOG_DEBUG() << "Timeout in collecting venous image";
    }
    else if (ret == -3)
    {
        KLOG_DEBUG() << "Collection operation canceled";
    }
    else if (ret != GENERAL_RESULT_OK)
    {
        KLOG_DEBUG() << "Failed to collect digital vein image" << ret;
    }
    else
    {
        /**
         * NOTE:录入和验证时，从图像中提取特征的函数不一样
         * TGImgExtractFeatureRegister  录入时使用
         * TGImgExtractFeatureVerify    验证时使用
         */

        // 录入时，返回image图像;验证/识别返回从图像中提取的特征
        if (deviceStatus() == DEVICE_STATUS_DOING_ENROLL)
        {
            QByteArray imageArray((char *)img, IMAGE_SIZE);
            return imageArray;
        }
        else
        {
            int result = m_driver->TGImgExtractFeatureVerify(img, IMAGE_ROI_WIDTH, IMAGE_ROI_HEIGHT, fs);
            if (result == GENERAL_RESULT_OK)
            {
                QByteArray fvTemplate((char *)fs, FEATURE_SIZE);
                return fvTemplate;
            }
            else
                KLOG_DEBUG() << "Failed to extract feature:" << ret;
        }
    }

    return QByteArray();
}

void FVSDDevice::acquireFeatureStop()
{
    m_driver->TGCancelGetImage();
}

void FVSDDevice::acquireFeatureFail()
{
    if (deviceStatus() == DEVICE_STATUS_DOING_ENROLL)
    {
        notifyEnrollProcess(ENROLL_PROCESS_ACQUIRE_FEATURE_FAIL);
        /**
         * NOTE:由于SD指静脉设备获取特征，必须传入一个TIME_OUT参数，所以会有超时的情况
         * 但是对于对外提供的IdentifyStart() 没有超时的概念
         */
        Q_EMIT this->retry();
    }
    else if (deviceStatus() == DEVICE_STATUS_DOING_IDENTIFY)
    {
        notifyIdentifyProcess(IDENTIFY_PROCESS_ACQUIRE_FEATURE_FAIL);
        Q_EMIT this->retry();
    }
}

void FVSDDevice::enrollProcessRetry()
{
    int voice = (0 == m_enrollTemplates.count()) ? VOICE_PLS_PUT_SOFTLY : VOICE_PLS_REPUT;
    m_driver->TGPlayDevVoice(voice);
    KLOG_DEBUG() << "Please put your finger in";
    Q_EMIT this->retry();
}

void FVSDDevice::saveEnrollTemplateToCache(QByteArray image)
{
    QByteArray featureForEnroll = getFeatureFromImage(image, EXTRACT_FEATURE_REGISTER);
    if (!featureForEnroll.isEmpty())
    {
        m_enrollTemplates << featureForEnroll;
        KLOG_DEBUG() << "enroll template:" << featureForEnroll;
        notifyEnrollProcess(ENROLL_PROCESS_PASS);
    }
}

/**
 * NOTE:短时间内播放两次声音，前一次未结束的话，会被后面的声音覆盖
 * 重复录入的声音 会被 下一次录入的播放声音覆盖
 */
void FVSDDevice::templateMerge()
{
    QByteArray multiFeature;
    Q_FOREACH (auto enrollTemplate, m_enrollTemplates)
    {
        multiFeature.append(enrollTemplate);
    }

    unsigned char tmpl[TEMPLATE_SIZE] = {0};  // 指静脉模板(存储)

    // 将六次指静脉融合为一个模板
    int ret = m_driver->TGFeaturesFusionTmpl((unsigned char *)multiFeature.data(), TEMPLATE_FV_NUM, tmpl);
    QByteArray mergedTemplate((char *)tmpl, TEMPLATE_SIZE);
    KLOG_DEBUG() << "mergedTemplate:" << mergedTemplate;

    if (ret == GENERAL_RESULT_OK)
    {
        QString id = QCryptographicHash::hash(mergedTemplate, QCryptographicHash::Md5).toHex();

        DeviceInfo deviceInfo = this->deviceInfo();
        bool save = FeatureDB::getInstance()->addFeature(id, mergedTemplate, deviceInfo, deviceType());
        if (save)
        {
            notifyEnrollProcess(ENROLL_PROCESS_SUCCESS, id);
            // 绿灯亮
            m_driver->TGSetDevLed(1, 0, 1);
            m_driver->TGPlayDevVoice(VOICE_REG_SUCCESS);
        }
        else
        {
            m_driver->TGPlayDevVoice(VOICE_REG_FAIL);
            notifyEnrollProcess(ENROLL_PROCESS_SAVE_FAIL);
        }
    }
    else
    {
        // 红亮
        m_driver->TGSetDevLed(1, 1, 0);
        m_driver->TGPlayDevVoice(VOICE_REG_FAIL);
        KLOG_DEBUG() << "Finger vein template fusion failed:" << ret;
        notifyEnrollProcess(ENROLL_PROCESS_MEGER_FAIL);
    }
}

QString FVSDDevice::isFeatureEnrolled(QByteArray fpTemplate)
{
    QByteArray featureForVerify = getFeatureFromImage(fpTemplate, EXTRACT_FEATURE_VERIFY);
    QList<QByteArray> features = FeatureDB::getInstance()->getFeatures(deviceInfo().idVendor, deviceInfo().idProduct, deviceType(), deviceSerialNumber());
    QString featureID = identifyFeature(featureForVerify, features);
    return featureID;
}

QString FVSDDevice::identifyFeature(QByteArray feature, QList<QByteArray> existedfeatures)
{
    QString featureID;
    QByteArray saveTempl;
    Q_FOREACH (auto saveFeature, existedfeatures)
    {
        saveTempl.append(saveFeature);
    }

    int matchIndex = 0;
    int matchScore = 0;
    unsigned char updateTmpl[TEMPLATE_SIZE] = {0};  // 自我学习后的新模板

    int matchResult = m_driver->TGFeatureMatchTmpl1N((unsigned char *)feature.data(),
                                                     (unsigned char *)saveTempl.data(),
                                                     existedfeatures.count(),
                                                     &matchIndex,
                                                     &matchScore,
                                                     updateTmpl);

    // 存在更新的模板
    // 在数据库中替换掉原来的模板，保持FeatureID不变
    if (matchResult == GENERAL_RESULT_OK)
    {
        QByteArray matchedFeature = saveTempl.mid((matchIndex - 1) * TEMPLATE_SIZE, TEMPLATE_SIZE);
        featureID = FeatureDB::getInstance()->getFeatureID(matchedFeature);

        QByteArray updateFeature((char *)updateTmpl, TEMPLATE_SIZE);
        bool result = FeatureDB::getInstance()->updateFeature(featureID, updateFeature);
        if (!result)
            KLOG_DEBUG() << "update feature failed!";
        KLOG_DEBUG() << "identifyFeature match success";
    }
    else
    {
        KLOG_DEBUG() << "matchResult:" << matchResult;
    }

    return featureID;
}

QByteArray FVSDDevice::getFeatureFromImage(QByteArray image, ExtractFeatureMode mode)
{
    unsigned char fs[FEATURE_SIZE] = {0};  // 指静脉特征
    int result;
    if (mode == EXTRACT_FEATURE_REGISTER)
    {
        result = m_driver->TGImgExtractFeatureRegister((unsigned char *)image.data(), IMAGE_ROI_WIDTH, IMAGE_ROI_HEIGHT, fs);
    }
    else
    {
        result = m_driver->TGImgExtractFeatureVerify((unsigned char *)image.data(), IMAGE_ROI_WIDTH, IMAGE_ROI_HEIGHT, fs);
    }

    if (result == GENERAL_RESULT_OK)
    {
        QByteArray fvTemplate((char *)fs, FEATURE_SIZE);
        return fvTemplate;
    }
    else
        KLOG_DEBUG() << "Failed to extract feature:" << result;

    return QByteArray();
}

int FVSDDevice::templateMatch(QByteArray fpTemplate1, QByteArray fpTemplate2)
{
    /**
     * NOTE:
     * 1、判断录入时是否录的是同一根手指，此处的更新模板不需要
     * 2、SD设备不支持在录入时，对采集到的两个未特征融合的特征进行一对一匹配
     *    只有特征融合后才能进行匹配
     */
    return GENERAL_RESULT_OK;
}

void FVSDDevice::notifyEnrollProcess(EnrollProcess process, const QString &featureID)
{
    QString message;
    switch (process)
    {
    case ENROLL_PROCESS_ACQUIRE_FEATURE_FAIL:
        message = tr("Finger vein image not obtained");
        Q_EMIT m_dbusAdaptor->EnrollStatus("", 0, ENROLL_STATUS_RETRY, message);
        break;
    case ENROLL_PROCESS_PASS:
        message = tr("Partial finger vein feature entry,please continue to place your finger");
        Q_EMIT m_dbusAdaptor->EnrollStatus("", enrollTemplatesFromCache().count() * 15, ENROLL_STATUS_PASS, message);
        break;
    case ENROLL_PROCESS_REPEATED_ENROLL:
        message = tr("The finger vein has been enrolled");
        Q_EMIT m_dbusAdaptor->EnrollStatus(featureID, 0, ENROLL_STATUS_FAIL, message);
        break;
    case ENROLL_PROCESS_INCONSISTENT_FEATURE:
        message = tr("Please place the same finger!");
        Q_EMIT m_dbusAdaptor->EnrollStatus("", enrollTemplatesFromCache().count() * 15, ENROLL_STATUS_RETRY, message);
        break;
    case ENROLL_PROCESS_MEGER_FAIL:
        message = tr("Finger vein template merged failed");
        Q_EMIT m_dbusAdaptor->EnrollStatus("", 0, ENROLL_STATUS_FAIL, message);
        break;
    case ENROLL_PROCESS_SUCCESS:
        message = tr("Successed save feature");
        Q_EMIT m_dbusAdaptor->EnrollStatus(featureID, 100, ENROLL_STATUS_COMPLETE, message);
        break;
    case ENROLL_PROCESS_SAVE_FAIL:
        message = tr("Save Feature Failed!");
        Q_EMIT m_dbusAdaptor->EnrollStatus("", 0, ENROLL_STATUS_FAIL, message);
        break;
    case ENROLL_PROCESS_INCONSISTENT_FEATURE_AFTER_MERGED:
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

void FVSDDevice::notifyIdentifyProcess(IdentifyProcess process, const QString &featureID)
{
    QString message;
    switch (process)
    {
    case IDENTIFY_PROCESS_ACQUIRE_FEATURE_FAIL:
        message = tr("timeout, acquire finger vein fail!");
        Q_EMIT m_dbusAdaptor->IdentifyStatus("", IDENTIFY_STATUS_RETRY, message);
        break;
    case IDENTIFY_PROCESS_MACTCH:
        message = tr("Feature Match");
        Q_EMIT m_dbusAdaptor->IdentifyStatus(featureID, IDENTIFY_STATUS_MATCH, message);
        m_driver->TGSetDevLed(1, 0, 1);                 // 绿灯亮
        m_driver->TGPlayDevVoice(VOICE_IDENT_SUCCESS);  // 语音:认证成功
        break;
    case IDENTIFY_PROCESS_NO_MATCH:
        message = tr("Feature not match, place again");
        Q_EMIT m_dbusAdaptor->IdentifyStatus(featureID, IDENTIFY_STATUS_NOT_MATCH, message);
        m_driver->TGSetDevLed(1, 1, 0);
        m_driver->TGPlayDevVoice(VOICE_IDENT_FAIL);
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
