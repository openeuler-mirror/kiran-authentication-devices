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

#include "fv-sd-device.h"
#include <dlfcn.h>
#include <qt5-log-i.h>
#include <unistd.h>
#include <QFuture>
#include <QtConcurrent>
#include "auth-enum.h"
#include "auth_device_adaptor.h"
#include "feature-db.h"
#include "third-party-device.h"
#include "utils.h"

namespace Kiran
{

#define SD_FV_TEMPLATE_NUM 6         // 注册登记模板时，需要采集的指静脉次数
#define SD_ENROLL_TIME_OUT 300       /* 入录指静脉等待时间，单位秒*/
#define SD_TEMPLATE_MAX_NUMBER 10000 /* 最大指纹模板数目 */

#define IMAGE_TIME_OUT 50                                      // 获取图像等待的时间,单位秒（即：超过这个时间没有检测到touch就返回）,经过简单测试该设备最大等待时间为50s
#define IMAGE_ROI_WIDTH 500                                    // 图像宽度
#define IMAGE_ROI_HEIGHT 200                                   // 图像高度
#define IMAGE_SIZE (IMAGE_ROI_WIDTH * IMAGE_ROI_HEIGHT + 208)  // 图片大小

#define FEATURE_SIZE 1024   // 指静脉特征值大小
#define TEMPLATE_SIZE 6144  // 指静脉模板大小

#define TEMPLATE_FV_NUM 6  // 注册登记模板时，需要采集的指静脉次数

#define SD_FV_DRIVER_LIB "sdfv"  // 该名称不是实际so名称，由于实际驱动由多个so组成，为了表示方便自定义了一个名称进行标识
#define SD_FV_DRIVER_LIB_PROCESS "libTGFVProcessAPI.so"
#define SD_FV_DRIVER_LIB_COM "libTGVM661JComAPI.so"
#define SD_LICENSE_PATH "/usr/share/kiran-authentication-devices-sdk/sd/license.dat"

#define VOICE_BI 0x00              // Bi
#define VOICE_BIBI 0x01            // BiBi
#define VOICE_REG_SUCCESS 0x02     // 登记成功
#define VOICE_REG_FAIL 0x03        // 登记失败
#define VOICE_PLS_REPUT 0x04       // 请再放一次
#define VOICE_PLS_PUT_CRUCLY 0x05  // 请正确放入手指
#define VOICE_PLS_PUT_SOFTLY 0x06  // 请自然轻放手指
#define VOICE_IDENT_SUCCESS 0x07   // 验证成功
#define VOICE_IDENT_FAIL 0x08      // 验证失败
#define VOICE_PLS_REDO 0x09        // 请重试
#define VOICE_DEL_SUCCESS 0x0A     // 删除成功
#define VOICE_DEL_FAIL 0x0B        // 删除失败
#define VOICE_VEIN_FULL 0x0C       // 指静脉已满
#define VOICE_REREG 0x0D           // 登记重复
#define VOICE_VOLUME0 0xF0         // 静音
#define VOICE_VOLUME1 0xF2         // 音量级别1
#define VOICE_VOLUME2 0xF4         // 音量级别2
#define VOICE_VOLUME3 0xF6         // 音量级别3
#define VOICE_VOLUME4 0xF8         // 音量级别4
#define VOICE_VOLUME5 0xFA         // 音量级别5
#define VOICE_VOLUME6 0xFC         // 音量级别6
#define VOICE_VOLUME7 0xFE         // 音量级别7

extern "C"
{
    // libTGFVProcessAPI.so
    typedef int (*TGInitFVProcessFunc)(const char *licenseDatPath);
    typedef int (*TGImgExtractFeatureVerifyFunc)(unsigned char *encryptImg, int imgWidth, int imgHeight, unsigned char *feature);
    typedef int (*TGFeaturesFusionTmplFunc)(unsigned char *features, int featureSize, unsigned char *tmpl);
    typedef int (*TGFeatureMatchTmpl1NFunc)(unsigned char *feature, unsigned char *matchTmplStart, int matchTmplNum, int *matchIndex, int *matchScore, unsigned char *updateTmpl);
    typedef int (*TGImgExtractFeatureRegisterFunc)(unsigned char *encryptImg, int imgWidth, int imgHeight, unsigned char *feature);

    // libTGVM661JComAPI.so
    typedef int (*TGOpenDevFunc)(int *mode);
    typedef int (*TGGetDevStatusFunc)();
    typedef int (*TGCloseDevFunc)();
    typedef int (*TGGetDevFWFunc)(char *fw);
    typedef int (*TGGetDevSNFunc)(char *sn);
    typedef int (*TGPlayDevVoiceFunc)(int voiceValue);
    typedef int (*TGGetDevImageFunc)(unsigned char *imageData, int timeout);
    typedef int (*TGCancelGetImageFunc)();
    typedef int (*TGSetDevLedFunc)(int ledBlue, int ledGreen, int ledRed);
}

struct DriverLib
{
    // libTGFVProcessAPI.so
    TGInitFVProcessFunc TGInitFVProcess;
    TGImgExtractFeatureVerifyFunc TGImgExtractFeatureVerify;
    TGFeaturesFusionTmplFunc TGFeaturesFusionTmpl;
    TGFeatureMatchTmpl1NFunc TGFeatureMatchTmpl1N;
    TGImgExtractFeatureRegisterFunc TGImgExtractFeatureRegister;

    // libTGVM661JComAPI.so
    TGOpenDevFunc TGOpenDev;
    TGGetDevStatusFunc TGGetDevStatus;
    TGCloseDevFunc TGCloseDev;
    TGGetDevFWFunc TGGetDevFW;
    TGGetDevSNFunc TGGetDevSN;
    TGPlayDevVoiceFunc TGPlayDevVoice;
    TGGetDevImageFunc TGGetDevImage;
    TGCancelGetImageFunc TGCancelGetImage;
    TGSetDevLedFunc TGSetDevLed;
};

FVSDDevice::FVSDDevice(QObject *parent) : AuthDevice{parent},
                                          m_driverLib(nullptr),
                                          m_libProcessHandle(nullptr),
                                          m_libComHandle(nullptr)
{
    setDeviceType(DEVICE_TYPE_FingerVein);
    setDeviceDriver(SD_FV_DRIVER_LIB);
}

FVSDDevice::~FVSDDevice()
{
    if (!deviceID().isEmpty())
    {
        acquireFeatureStop();
        m_futureWatcher->deleteLater();
        KLOG_DEBUG() << "TGGetDevStatus():" << m_driverLib->TGGetDevStatus();
        m_driverLib->TGCloseDev();
    }

    if (m_driverLib)
    {
        delete m_driverLib;
        m_driverLib = nullptr;
    }

    if (m_libComHandle)
    {
        dlclose(m_libComHandle);
        m_libComHandle = NULL;
    }

    if (m_libProcessHandle)
    {
        dlclose(m_libProcessHandle);
        m_libProcessHandle = NULL;
    }
}

bool FVSDDevice::loadLib()
{
    // 打开指定的动态链接库文件；立刻决定返回前接触所有未决定的符号。若打开错误返回NULL，成功则返回库引用
    m_libProcessHandle = dlopen(SD_FV_DRIVER_LIB_PROCESS, RTLD_NOW);
    if (m_libProcessHandle == NULL)
    {
        KLOG_ERROR() << "Load libTGFVProcessAPI failed,error:" << dlerror();
        return false;
    }

    m_libComHandle = dlopen(SD_FV_DRIVER_LIB_COM, RTLD_NOW);
    if (m_libComHandle == NULL)
    {
        KLOG_ERROR() << "Load libTGVM661JComAPI failed,error:" << dlerror();
        return false;
    }

    m_driverLib = new DriverLib;
    m_driverLib->TGInitFVProcess = (TGInitFVProcessFunc)dlsym(m_libProcessHandle, "TGInitFVProcess");
    m_driverLib->TGImgExtractFeatureVerify = (TGImgExtractFeatureVerifyFunc)dlsym(m_libProcessHandle, "TGImgExtractFeatureVerify");
    m_driverLib->TGFeaturesFusionTmpl = (TGFeaturesFusionTmplFunc)dlsym(m_libProcessHandle, "TGFeaturesFusionTmpl");
    m_driverLib->TGFeatureMatchTmpl1N = (TGFeatureMatchTmpl1NFunc)dlsym(m_libProcessHandle, "TGFeatureMatchTmpl1N");
    m_driverLib->TGImgExtractFeatureRegister = (TGImgExtractFeatureRegisterFunc)dlsym(m_libProcessHandle, "TGImgExtractFeatureRegister");

    m_driverLib->TGOpenDev = (TGOpenDevFunc)dlsym(m_libComHandle, "TGOpenDev");
    m_driverLib->TGGetDevStatus = (TGGetDevStatusFunc)dlsym(m_libComHandle, "TGGetDevStatus");
    m_driverLib->TGCloseDev = (TGCloseDevFunc)dlsym(m_libComHandle, "TGCloseDev");
    m_driverLib->TGGetDevFW = (TGGetDevFWFunc)dlsym(m_libComHandle, "TGGetDevFW");
    m_driverLib->TGGetDevSN = (TGGetDevSNFunc)dlsym(m_libComHandle, "TGGetDevSN");
    m_driverLib->TGPlayDevVoice = (TGPlayDevVoiceFunc)dlsym(m_libComHandle, "TGPlayDevVoice");
    m_driverLib->TGGetDevImage = (TGGetDevImageFunc)dlsym(m_libComHandle, "TGGetDevImage");
    m_driverLib->TGCancelGetImage = (TGCancelGetImageFunc)dlsym(m_libComHandle, "TGCancelGetImage");
    m_driverLib->TGSetDevLed = (TGSetDevLedFunc)dlsym(m_libComHandle, "TGSetDevLed");

    return true;
}

bool FVSDDevice::initDevice()
{
    if (!loadLib())
    {
        return false;
    }

    int ret = -1;
    int mode = 0;
    char fw[32] = {0};
    char sn[32] = {0};
    // 初始化算法
    ret = m_driverLib->TGInitFVProcess(SD_LICENSE_PATH);
    if (ret != GENERAL_RESULT_OK)
    {
        KLOG_DEBUG() << "Initialization algorithm failed:" << ret;
        return false;
    }
    KLOG_DEBUG() << "Initialization algorithm succeeded";
    // 打开设备
    ret = m_driverLib->TGOpenDev(&mode);
    if (ret != GENERAL_RESULT_OK)
    {
        KLOG_DEBUG() << "Failed to open device:" << ret;
        return false;
    }

    KLOG_DEBUG() << "TGGetDevStatus():" << m_driverLib->TGGetDevStatus();
    if (m_driverLib->TGGetDevStatus() < 0)
    {
        KLOG_DEBUG() << "device not connected";
        return false;
    }
    KLOG_DEBUG() << "Device opened successfully:" << ret;

    ret = m_driverLib->TGGetDevFW(fw);
    KLOG_DEBUG() << "Get firmware version:" << fw;
    ret = m_driverLib->TGGetDevSN(sn);
    KLOG_DEBUG() << "Obtain device SN number:" << sn;
    ret = m_driverLib->TGPlayDevVoice(VOICE_VOLUME1);

    return true;
}

QByteArray FVSDDevice::acquireFeature()
{
    unsigned char img[IMAGE_SIZE] = {0};   // 指静脉图像(建议保存存储)
    unsigned char fs[FEATURE_SIZE] = {0};  // 指静脉特征

    if (deviceStatus() == DEVICE_STATUS_DOING_ENROLL)
    {
        int voice = (0 == m_enrollTemplates.count()) ? VOICE_PLS_PUT_SOFTLY : VOICE_PLS_REPUT;
        m_driverLib->TGPlayDevVoice(voice);
        KLOG_DEBUG() << "Please put your finger in";
    }
    else
        m_driverLib->TGPlayDevVoice(VOICE_PLS_PUT_SOFTLY);
    // 采集指静脉图像
    int ret = m_driverLib->TGGetDevImage(img, IMAGE_TIME_OUT);
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
            int result = m_driverLib->TGImgExtractFeatureVerify(img, IMAGE_ROI_WIDTH, IMAGE_ROI_HEIGHT, fs);
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
    m_driverLib->TGCancelGetImage();
    if (m_futureWatcher != nullptr)
    {
        m_futureWatcher->waitForFinished();
    }
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
    m_driverLib->TGPlayDevVoice(voice);
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
void FVSDDevice::enrollTemplateMerge()
{
    QByteArray multiFeature;
    Q_FOREACH (auto enrollTemplate, m_enrollTemplates)
    {
        multiFeature.append(enrollTemplate);
    }

    unsigned char tmpl[TEMPLATE_SIZE] = {0};  // 指静脉模板(存储)

    // 将六次指静脉融合为一个模板
    int ret = m_driverLib->TGFeaturesFusionTmpl((unsigned char *)multiFeature.data(), TEMPLATE_FV_NUM, tmpl);
    QByteArray mergedTemplate((char *)tmpl, TEMPLATE_SIZE);
    KLOG_DEBUG() << "mergedTemplate:" << mergedTemplate;

    if (ret == GENERAL_RESULT_OK)
    {
        QString id = QCryptographicHash::hash(mergedTemplate, QCryptographicHash::Md5).toHex();

        DeviceInfo deviceInfo;
        deviceInfo.idVendor = m_idVendor;
        deviceInfo.idProduct = m_idProduct;
        bool save = FeatureDB::getInstance()->addFeature(id, mergedTemplate, deviceInfo);
        if (save)
        {
            notifyEnrollProcess(ENROLL_PROCESS_SUCCESS, id);
            // 绿灯亮
            m_driverLib->TGSetDevLed(1, 0, 1);
            m_driverLib->TGPlayDevVoice(VOICE_REG_SUCCESS);
        }
        else
        {
            m_driverLib->TGPlayDevVoice(VOICE_REG_FAIL);
            notifyEnrollProcess(ENROLL_PROCESS_SAVE_FAIL);
        }
    }
    else
    {
        // 红亮
        m_driverLib->TGSetDevLed(1, 1, 0);
        m_driverLib->TGPlayDevVoice(VOICE_REG_FAIL);
        KLOG_DEBUG() << "Finger vein template fusion failed:" << ret;
        notifyEnrollProcess(ENROLL_PROCESS_MEGER_FAIL);
    }
    internalStopEnroll();
}

QString FVSDDevice::isFeatureEnrolled(QByteArray fpTemplate)
{
    QByteArray featureForVerify = getFeatureFromImage(fpTemplate, EXTRACT_FEATURE_VERIFY);
    QString featureID = identifyFeature(featureForVerify, QStringList());
    return featureID;
}

QString FVSDDevice::identifyFeature(QByteArray feature, QStringList featureIDs)
{
    QList<QByteArray> saveList;
    QString featureID;
    if (featureIDs.isEmpty())
    {
        saveList = FeatureDB::getInstance()->getFeatures(m_idVendor, m_idProduct);
    }
    else
    {
        Q_FOREACH (auto id, featureIDs)
        {
            QByteArray feature = FeatureDB::getInstance()->getFeature(id);
            if (!feature.isEmpty())
                saveList << feature;
        }
    }

    if (saveList.count() != 0)
    {
        QByteArray saveTempl;
        Q_FOREACH (auto saveFeature, saveList)
        {
            saveTempl.append(saveFeature);
        }

        int matchIndex = 0;
        int matchScore = 0;
        unsigned char updateTmpl[TEMPLATE_SIZE] = {0};  // 自我学习后的新模板
        KLOG_DEBUG() << "saveList.count():" << saveList.count();

        int matchResult = m_driverLib->TGFeatureMatchTmpl1N((unsigned char *)feature.data(),
                                                            (unsigned char *)saveTempl.data(),
                                                            saveList.count(),
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
    }

    return featureID;
}

QByteArray FVSDDevice::getFeatureFromImage(QByteArray image, ExtractFeatureMode mode)
{
    unsigned char fs[FEATURE_SIZE] = {0};  // 指静脉特征
    int result;
    if (mode == EXTRACT_FEATURE_REGISTER)
    {
        result = m_driverLib->TGImgExtractFeatureRegister((unsigned char *)image.data(), IMAGE_ROI_WIDTH, IMAGE_ROI_HEIGHT, fs);
    }
    else
    {
        result = m_driverLib->TGImgExtractFeatureVerify((unsigned char *)image.data(), IMAGE_ROI_WIDTH, IMAGE_ROI_HEIGHT, fs);
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

BDriver *FVSDDevice::getDriver()
{
    return nullptr;
}

int FVSDDevice::needTemplatesCountForEnroll()
{
    return TEMPLATE_FV_NUM;
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
        Q_EMIT m_dbusAdaptor->EnrollStatus("", 0, ENROLL_RESULT_RETRY, message);
        KLOG_DEBUG() << message;
        break;
    case ENROLL_PROCESS_PASS:
        message = tr("Partial finger vein feature entry");
        Q_EMIT m_dbusAdaptor->EnrollStatus("", enrollTemplatesFromCache().count() * 15, ENROLL_RESULT_PASS, message);
        break;
    case ENROLL_PROCESS_REPEATED_ENROLL:
        message = tr("The finger vein has been enrolled");
        Q_EMIT m_dbusAdaptor->EnrollStatus(featureID, 0, ENROLL_RESULT_FAIL, message);
        break;
    case ENROLL_PROCESS_INCONSISTENT_FEATURE:
        message = tr("Please place the same finger!");
        Q_EMIT m_dbusAdaptor->EnrollStatus("", enrollTemplatesFromCache().count() * 15, ENROLL_RESULT_RETRY, message);
        break;
    case ENROLL_PROCESS_MEGER_FAIL:
        message = tr("Finger vein template merged failed");
        Q_EMIT m_dbusAdaptor->EnrollStatus("", 0, ENROLL_RESULT_FAIL, message);
        break;
    case ENROLL_PROCESS_SUCCESS:
        message = tr("Successed save feature");
        Q_EMIT m_dbusAdaptor->EnrollStatus(featureID, 100, ENROLL_RESULT_COMPLETE, message);
        break;
    case ENROLL_PROCESS_SAVE_FAIL:
        message = tr("Save Feature Failed!");
        Q_EMIT m_dbusAdaptor->EnrollStatus("", 0, ENROLL_RESULT_FAIL, message);
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
        Q_EMIT m_dbusAdaptor->IdentifyStatus("", IDENTIFY_RESULT_RETRY, message);
        break;
    case IDENTIFY_PROCESS_MACTCH:
        message = tr("Feature Match");
        Q_EMIT m_dbusAdaptor->IdentifyStatus(featureID, IDENTIFY_RESULT_MATCH, message);
        m_driverLib->TGSetDevLed(1, 0, 1);                 // 绿灯亮
        m_driverLib->TGPlayDevVoice(VOICE_IDENT_SUCCESS);  // 语音:认证成功
        break;
    case IDENTIFY_PROCESS_NO_MATCH:
        message = tr("Feature not match, place again");
        Q_EMIT m_dbusAdaptor->IdentifyStatus(featureID, IDENTIFY_RESULT_NOT_MATCH, message);
        m_driverLib->TGSetDevLed(1, 1, 0);
        m_driverLib->TGPlayDevVoice(VOICE_IDENT_FAIL);
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
