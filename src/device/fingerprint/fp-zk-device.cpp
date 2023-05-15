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

#include <QFuture>
#include <QtConcurrent>
#include "feature-db.h"

#include "utils.h"

namespace Kiran
{
#define FP_TEMPLATE_MAX_NUMBER 10000 /* 最大指纹模板数目 */
#define FP_TIME_OUT 600000           /* 一次等待指纹时间，单位毫秒*/
#define FP_MAX_TRY_COUNT 10          /* 最大尝试次数 */

#define FP_ZK_PARAM_CODE_VID_PID 1015
#define FP_ZK_PARAM_CODE_VENDOR_NAME 1101
#define FP_ZK_PARAM_CODE_PRODUCT_NAME 1102
#define FP_ZK_PARAM_CODE_SERIAL_NUNBER 1103
#define FP_ZK_MAX_TEMPLATE_SIZE 2048 /*模板最大长度 */

#define FP_ZK_DRIVER_LIB "libzkfp.so"
#define FP_ZK_MEGER_TEMPLATE_COUNT 3

#define ZKFP_ERR_ALREADY_INIT 1        /*已经初始化 */
#define ZKFP_ERR_OK 0                  /*操作成功 */
#define ZKFP_ERR_INITLIB -1            /*初始化算法库失败 */
#define ZKFP_ERR_INIT -2               /*初始化采集库失败 */
#define ZKFP_ERR_NO_DEVICE -3          /*无设备连接 */
#define ZKFP_ERR_NOT_SUPPORT -4        /*接口暂不支持 */
#define ZKFP_ERR_INVALID_PARAM -5      /*无效参数 */
#define ZKFP_ERR_OPEN -6               /*打开设备失败 */
#define ZKFP_ERR_INVALID_HANDLE -7     /*无效句柄 */
#define ZKFP_ERR_CAPTURE -8            /*取像失败 */
#define ZKFP_ERR_EXTRACT_FP -9         /*提取指纹模板失败 */
#define ZKFP_ERR_ABSORT -10            /*中断 */
#define ZKFP_ERR_MEMORY_NOT_ENOUGH -11 /*内存不足 */
#define ZKFP_ERR_BUSY -12              /*当前正在采集 */
#define ZKFP_ERR_ADD_FINGER -13        /*添加指纹模板失败 */
#define ZKFP_ERR_DEL_FINGER -14        /*删除指纹失败 */
#define ZKFP_ERR_FAIL -17              /*操作失败 */
#define ZKFP_ERR_CANCEL -18            /*取消采集 */
#define ZKFP_ERR_VERIFY_FP -20         /*比对指纹失败 */
#define ZKFP_ERR_MERGE -22             /*合并登记指纹模板失败	*/
#define ZKFP_ERR_NOT_OPENED -23;       /*设备未打开	*/
#define ZKFP_ERR_NOT_INIT -24;         /*未初始化	*/
#define ZKFP_ERR_ALREADY_OPENED -25;   /*设备已打开	*/
#define ZKFP_ERR_LOADIMAGE -26         /*文件打开失败			*/
#define ZKFP_ERR_ANALYSE_IMG -27       /*处理图像失败			*/
#define ZKFP_ERR_TIMEOUT -28           /*超时					*/

extern "C"
{
    typedef int (*T_ZKFPM_Init)();
    typedef int (*T_ZKFPM_Terminate)();
    typedef int (*T_ZKFPM_GetDeviceCount)();
    typedef HANDLE (*T_ZKFPM_OpenDevice)(int index);
    typedef int (*T_ZKFPM_CloseDevice)(HANDLE hDevice);
    typedef int (*T_ZKFPM_SetParameters)(HANDLE hDevice, int nParamCode, unsigned char* paramValue, unsigned int cbParamValue);
    typedef int (*T_ZKFPM_GetParameters)(HANDLE hDevice, int nParamCode, unsigned char* paramValue, unsigned int* cbParamValue);
    typedef int (*T_ZKFPM_AcquireFingerprint)(HANDLE hDevice, unsigned char* fpImage, unsigned int cbFPImage, unsigned char* fpTemplate, unsigned int* cbTemplate);
    typedef int (*T_ZKFPM_AcquireFingerprintImage)(HANDLE hDevice, unsigned char* fpImage, unsigned int cbFPImage);

    typedef HANDLE (*T_ZKFPM_DBInit)();
    typedef int (*T_ZKFPM_DBFree)(HANDLE hDBCache);
    typedef int (*T_ZKFPM_DBMerge)(HANDLE hDBCache, unsigned char* temp1, unsigned char* temp2, unsigned char* temp3, unsigned char* regTemp, unsigned int* cbRegTemp);
    typedef int (*T_ZKFPM_DBAdd)(HANDLE hDBCache, unsigned int fid, unsigned char* fpTemplate, unsigned int cbTemplate);
    typedef int (*T_ZKFPM_DBDel)(HANDLE hDBCache, unsigned int fid);
    typedef int (*T_ZKFPM_DBClear)(HANDLE hDBCache);
    typedef int (*T_ZKFPM_DBCount)(HANDLE hDBCache, unsigned int* fpCount);
    typedef int (*T_ZKFPM_DBIdentify)(HANDLE hDBCache, unsigned char* fpTemplate, unsigned int cbTemplate, unsigned int* FID, unsigned int* score);
    typedef int (*T_ZKFPM_DBMatch)(HANDLE hDBCache, unsigned char* template1, unsigned int cbTemplate1, unsigned char* template2, unsigned int cbTemplate2);
    typedef int (*T_ZKFPM_ExtractFromImage)(HANDLE hDBCache, const char* lpFilePathName, unsigned int DPI, unsigned char* fpTemplate, unsigned int* cbTemplate);

    typedef void (*T_ZKFPM_SetLogLevel)(int nLevel);
    typedef void (*T_ZKFPM_ConfigLog)(int nLevel, int nType, char* fileName);
};

struct DriverLib
{
    T_ZKFPM_Init ZKFPM_Init;
    T_ZKFPM_Terminate ZKFPM_Terminate;
    T_ZKFPM_GetDeviceCount ZKFPM_GetDeviceCount;
    T_ZKFPM_OpenDevice ZKFPM_OpenDevice;
    T_ZKFPM_CloseDevice ZKFPM_CloseDevice;
    T_ZKFPM_SetParameters ZKFPM_SetParameters;
    T_ZKFPM_GetParameters ZKFPM_GetParameters;
    T_ZKFPM_AcquireFingerprint ZKFPM_AcquireFingerprint;
    T_ZKFPM_AcquireFingerprintImage ZKFPM_AcquireFingerprintImage;

    T_ZKFPM_DBInit ZKFPM_DBInit;
    T_ZKFPM_DBFree ZKFPM_DBFree;
    T_ZKFPM_DBMerge ZKFPM_DBMerge;
    T_ZKFPM_DBAdd ZKFPM_DBAdd;
    T_ZKFPM_DBDel ZKFPM_DBDel;
    T_ZKFPM_DBClear ZKFPM_DBClear;
    T_ZKFPM_DBCount ZKFPM_DBCount;
    T_ZKFPM_DBIdentify ZKFPM_DBIdentify;
    T_ZKFPM_DBMatch ZKFPM_DBMatch;
    T_ZKFPM_ExtractFromImage ZKFPM_ExtractFromImage;

    T_ZKFPM_SetLogLevel ZKFPM_SetLogLevel;
    T_ZKFPM_ConfigLog ZKFPM_ConfigLog;
};

FPZKDevice::FPZKDevice(QObject* parent)
    : FPDevice{parent},
      m_hDBCache(nullptr),
      m_libHandle(nullptr),
      m_driverLib(nullptr)
{
    setDeviceType(DEVICE_TYPE_FingerPrint);
    setDeviceDriver(FP_ZK_DRIVER_LIB);
    setMergeTemplateCount(FP_ZK_MEGER_TEMPLATE_COUNT);
}

// 析构时对设备进行资源回收
FPZKDevice::~FPZKDevice()
{
    acquireFeatureStop();
    if (m_hDBCache)
    {
        m_driverLib->ZKFPM_DBFree(m_hDBCache);
        m_hDBCache = NULL;
    }

    if (m_driverLib.data())
    {
        m_driverLib->ZKFPM_Terminate();  // 释放资源
    }

    if (m_libHandle)
    {
        dlclose(m_libHandle);
        m_libHandle = NULL;
    }
}

bool FPZKDevice::initDevice()
{
    if (!loadLib())
    {
        return false;
    }

    int ret = m_driverLib->ZKFPM_Init();
    if (ret != ZKFP_ERR_OK)
    {
        return false;
    }

    m_hDBCache = m_driverLib->ZKFPM_DBInit();  // 创建算法缓冲区   返回值：缓冲区句柄
    if (NULL == m_hDBCache)
    {
        return false;
    }

    return true;
}

bool FPZKDevice::loadLib()
{
    // 打开指定的动态链接库文件；立刻决定返回前接触所有未决定的符号。若打开错误返回NULL，成功则返回库引用
    m_libHandle = dlopen(FP_ZK_DRIVER_LIB, RTLD_NOW);
    if (NULL == m_libHandle)
    {
        KLOG_ERROR() << "Load libzkfp failed,error:" << dlerror();
        return false;
    }

    m_driverLib = QSharedPointer<DriverLib>(new DriverLib);
    m_driverLib->ZKFPM_Init = (T_ZKFPM_Init)dlsym(m_libHandle, "ZKFPM_Init");
    if (NULL == m_driverLib->ZKFPM_Init)
    {
        return false;
    }

    m_driverLib->ZKFPM_Terminate = (T_ZKFPM_Terminate)dlsym(m_libHandle, "ZKFPM_Terminate");
    m_driverLib->ZKFPM_GetDeviceCount = (T_ZKFPM_GetDeviceCount)dlsym(m_libHandle, "ZKFPM_GetDeviceCount");
    m_driverLib->ZKFPM_OpenDevice = (T_ZKFPM_OpenDevice)dlsym(m_libHandle, "ZKFPM_OpenDevice");
    m_driverLib->ZKFPM_CloseDevice = (T_ZKFPM_CloseDevice)dlsym(m_libHandle, "ZKFPM_CloseDevice");
    m_driverLib->ZKFPM_SetParameters = (T_ZKFPM_SetParameters)dlsym(m_libHandle, "ZKFPM_SetParameters");
    m_driverLib->ZKFPM_GetParameters = (T_ZKFPM_GetParameters)dlsym(m_libHandle, "ZKFPM_GetParameters");
    m_driverLib->ZKFPM_AcquireFingerprint = (T_ZKFPM_AcquireFingerprint)dlsym(m_libHandle, "ZKFPM_AcquireFingerprint");
    m_driverLib->ZKFPM_DBInit = (T_ZKFPM_DBInit)dlsym(m_libHandle, "ZKFPM_DBInit");
    m_driverLib->ZKFPM_DBFree = (T_ZKFPM_DBFree)dlsym(m_libHandle, "ZKFPM_DBFree");
    m_driverLib->ZKFPM_DBMerge = (T_ZKFPM_DBMerge)dlsym(m_libHandle, "ZKFPM_DBMerge");
    m_driverLib->ZKFPM_DBDel = (T_ZKFPM_DBDel)dlsym(m_libHandle, "ZKFPM_DBDel");
    m_driverLib->ZKFPM_DBAdd = (T_ZKFPM_DBAdd)dlsym(m_libHandle, "ZKFPM_DBAdd");
    m_driverLib->ZKFPM_DBClear = (T_ZKFPM_DBClear)dlsym(m_libHandle, "ZKFPM_DBClear");
    m_driverLib->ZKFPM_DBCount = (T_ZKFPM_DBCount)dlsym(m_libHandle, "ZKFPM_DBCount");
    m_driverLib->ZKFPM_DBIdentify = (T_ZKFPM_DBIdentify)dlsym(m_libHandle, "ZKFPM_DBIdentify");
    m_driverLib->ZKFPM_DBMatch = (T_ZKFPM_DBMatch)dlsym(m_libHandle, "ZKFPM_DBMatch");
    m_driverLib->ZKFPM_SetLogLevel = (T_ZKFPM_SetLogLevel)dlsym(m_libHandle, "ZKFPM_SetLogLevel");
    m_driverLib->ZKFPM_ConfigLog = (T_ZKFPM_ConfigLog)dlsym(m_libHandle, "ZKFPM_ConfigLog");

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
        hDevice = m_driverLib->ZKFPM_OpenDevice(i);
        if (hDevice)
            break;
    }
    return hDevice;
}

QByteArray FPZKDevice::acquireFeature()
{
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
    m_doAcquire = true;

    memset(paramValue, 0x0, 4);  // 初始化paramValue[4]
    cbParamValue = 4;            // 初始化cbParamValue
    /* |   设备  |   参数类型     |  参数值     |  参数数据长度  */
    m_driverLib->ZKFPM_GetParameters(hDevice, 1, (unsigned char*)paramValue, &cbParamValue);  // 获取采集器参数 图像宽

    memset(paramValue, 0x0, 4);  // 初始化paramValue[4]
    cbParamValue = 4;            // 初始化cbParamValue
    /* |   设备  |   参数类型     |  参数值     |  参数数据长度  */
    m_driverLib->ZKFPM_GetParameters(hDevice, 2, (unsigned char*)paramValue, &cbParamValue);  // 获取采集器参数 图像高

    memset(paramValue, 0x0, 4);  // 初始化paramValue[4]
    cbParamValue = 4;            // 初始化cbParamValue
    /* |   设备  |   参数类型     |  参数值     |  参数数据长度  */
    m_driverLib->ZKFPM_GetParameters(hDevice, 106, (unsigned char*)paramValue, &cbParamValue);  // 获取采集器参数 图像数据大小

    imageBufferSize = *((int*)paramValue);
    pImgBuf = (unsigned char*)malloc(imageBufferSize);
    if (pImgBuf == NULL)
    {
        m_driverLib->ZKFPM_CloseDevice(hDevice);
        return QByteArray();
    }

    ret = GENERAL_RESULT_FAIL;

    while (m_doAcquire)
    {
        ret = m_driverLib->ZKFPM_AcquireFingerprint(hDevice,
                                                    pImgBuf, imageBufferSize,
                                                    szTemplate, &tempLen);
        if (ret == GENERAL_RESULT_OK)
        {
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

    m_driverLib->ZKFPM_CloseDevice(hDevice);

    return fpTemplate;
}

void FPZKDevice::acquireFeatureStop()
{
    m_doAcquire = false;
    if (m_futureWatcher.data() != nullptr)
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
    int ret = m_driverLib->ZKFPM_DBMerge(m_hDBCache,
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
    score = m_driverLib->ZKFPM_DBMatch(m_hDBCache,
                                       (unsigned char*)fpTemplate1.data(), fpTemplate1.size(),
                                       (unsigned char*)fpTemplate2.data(), fpTemplate2.size());

    return score > 0 ? GENERAL_RESULT_OK : GENERAL_RESULT_FAIL;
}


QString FPZKDevice::identifyFeature(QByteArray fpTemplate, QStringList featureIDs)
{
    QList<QByteArray> saveList;
    QString featureID;
    DeviceInfo info  = this->deviceInfo();
    if (featureIDs.isEmpty())
    {
        saveList = FeatureDB::getInstance()->getFeatures(info.idVendor, info.idProduct);
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
        for (int j = 0; j < saveList.count(); j++)
        {
            auto saveTemplate = saveList.value(j);
            int ret = enrollTemplateMatch(fpTemplate, saveTemplate);
            // 指纹已经存在，直接返回该指纹
            if (ret == GENERAL_RESULT_OK)
            {
                featureID = FeatureDB::getInstance()->getFeatureID(saveTemplate);
                break;
            }
        }
    }
    return featureID;
}

bool FPZKDevice::saveFPrintTemplate(QByteArray fpTemplate, const QString& featureID)
{
    DeviceInfo deviceInfo = this->deviceInfo();
    bool save = FeatureDB::getInstance()->addFeature(featureID, fpTemplate, deviceInfo);
    return save;
}

int FPZKDevice::getDevCount()
{
    return m_driverLib->ZKFPM_GetDeviceCount();
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
        internalStopEnroll();
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
    internalStopEnroll();
}

void FPZKDevice::notifyEnrollProcess(EnrollProcess process, const QString& featureID)
{
    QString message;
    switch (process)
    {
    case ENROLL_PROCESS_ACQUIRE_FEATURE_FAIL:
        message = tr("acquire fingerprint fail!");
        Q_EMIT m_dbusAdaptor->EnrollStatus("", 0, ENROLL_RESULT_FAIL, message);
        break;
    case ENROLL_PROCESS_PASS:
        message = tr("Partial fingerprint feature entry");
        Q_EMIT m_dbusAdaptor->EnrollStatus("", enrollTemplatesFromCache().count() * 25, ENROLL_RESULT_PASS, message);
        break;
    case ENROLL_PROCESS_REPEATED_ENROLL:
        message = tr("The fingerprint has been enrolled");
        Q_EMIT m_dbusAdaptor->EnrollStatus(featureID, 0, ENROLL_RESULT_FAIL, message);
        break;
    case ENROLL_PROCESS_INCONSISTENT_FEATURE:
        message = tr("Please place the same finger!");
        KLOG_DEBUG() << message;
        Q_EMIT m_dbusAdaptor->EnrollStatus("", enrollTemplatesFromCache().count() * 25, ENROLL_RESULT_RETRY, message);
        break;
    case ENROLL_PROCESS_MEGER_FAIL:
        message = tr("Failed to enroll fingerprint, please enroll again");
        Q_EMIT m_dbusAdaptor->EnrollStatus("", 0, ENROLL_RESULT_FAIL, message);
        break;
    case ENROLL_PROCESS_SUCCESS:
        message = tr("Successed save finger");
        Q_EMIT m_dbusAdaptor->EnrollStatus(featureID, 100, ENROLL_RESULT_COMPLETE, message);
        break;
    case ENROLL_PROCESS_SAVE_FAIL:
        message = tr("Save Finger Failed!");
        Q_EMIT m_dbusAdaptor->EnrollStatus("", 0, ENROLL_RESULT_FAIL, message);
        break;
    case ENROLL_PROCESS_INCONSISTENT_FEATURE_AFTER_MERGED:
        message = tr("Failed to enroll fingerprint, please enroll again");
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

void FPZKDevice::notifyIdentifyProcess(IdentifyProcess process, const QString& featureID)
{
    QString message;
    switch (process)
    {
    case IDENTIFY_PROCESS_TIME_OUT:
        break;
    case IDENTIFY_PROCESS_ACQUIRE_FEATURE_FAIL:
        message = tr("acquire fingerprint fail!");
        Q_EMIT m_dbusAdaptor->IdentifyStatus("", IDENTIFY_RESULT_NOT_MATCH, message);
        break;
    case IDENTIFY_PROCESS_MACTCH:
        message = tr("Fingerprint match");
        Q_EMIT m_dbusAdaptor->IdentifyStatus(featureID, IDENTIFY_RESULT_MATCH, message);
        break;
    case IDENTIFY_PROCESS_NO_MATCH:
        message = tr("Fingerprint not match, place again");
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
