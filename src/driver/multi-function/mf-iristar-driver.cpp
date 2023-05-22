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

#include "mf-iristar-driver.h"
#include <dlfcn.h>
#include <qt5-log-i.h>
#include <sys/time.h>
#include <QCryptographicHash>
#include <functional>
#include <iostream>
#include "auth_device_adaptor.h"
#include "feature-db.h"
#include "third-party-device.h"

namespace Kiran
{
template <typename T>
struct Callback;

template <typename Ret, typename... Params>
struct Callback<Ret(Params...)>
{
    template <typename... Args>
    static Ret callback(Args... args)
    {
        return func(args...);
    }
    static std::function<Ret(Params...)> func;
};

// Initialize the static member.
template <typename Ret, typename... Params>
std::function<Ret(Params...)> Callback<Ret(Params...)>::func;

#define IRIS_IS_DRIVER_LIB "libirs_sdk2.so"
#define IRIS_IS_STARTUP_CONFIG_PATH "/etc/kiran-authentication-devices-sdk/iristar/config/sdkcfg.ini"

#define IRIS_FEATURE_LEN 512   // 单个虹膜特征数据长度
#define FACE_FEATURE_LEN 2048  // 单个人脸特征数据长度

#define ALGORITHM_TYPE_IRIS "I"
#define ALGORITHM_TYPE_FACE "F"

extern "C"
{
    typedef int (*IRS_createInstance_Func)(IRS_Handle *, ...);
    typedef int (*IRS_releaseInstance_Func)(IRS_Handle);
    typedef int (*IRS_resetInstance_Func)(IRS_Handle);
    typedef int (*IRS_setParams_Func)(IRS_Handle, ...);
    typedef int (*IRS_setParamsByConfigFile_Func)(IRS_Handle, const char *configFileName, const char **sectionNames, int nb);
    typedef int (*IRS_setNParams_Func)(IRS_Handle, int nb, const IRS_ParamInitEntry *entry);
    typedef int (*IRS_getParams_Func)(IRS_Handle, ...);
    typedef int (*IRS_control_Func)(IRS_Handle, int ctrlId, void *data, int dataLen);
    typedef _IRS_MSG2_TYPE (*IRS_decodeMsg_Func)(IRS_Handle, IRS_Results *results);
}

struct IriStarDriverLib
{
    IRS_createInstance_Func IRS_createInstance;
    IRS_releaseInstance_Func IRS_releaseInstance;
    IRS_resetInstance_Func IRS_resetInstance;
    IRS_setParams_Func IRS_setParams;
    IRS_setParamsByConfigFile_Func IRS_setParamsByConfigFile;
    IRS_setNParams_Func IRS_setNParams;
    IRS_getParams_Func IRS_getParams;
    IRS_control_Func IRS_control;
    IRS_decodeMsg_Func IRS_decodeMsg;

    void loadSym(Handle libHandle)
    {
        this->IRS_createInstance = (IRS_createInstance_Func)dlsym(libHandle, "IRS_createInstance");
        this->IRS_releaseInstance = (IRS_releaseInstance_Func)dlsym(libHandle, "IRS_releaseInstance");
        this->IRS_resetInstance = (IRS_resetInstance_Func)dlsym(libHandle, "IRS_resetInstance");
        this->IRS_setParams = (IRS_setParams_Func)dlsym(libHandle, "IRS_setParams");
        this->IRS_setParamsByConfigFile = (IRS_setParamsByConfigFile_Func)dlsym(libHandle, "IRS_setParamsByConfigFile");
        this->IRS_setNParams = (IRS_setNParams_Func)dlsym(libHandle, "IRS_setNParams");
        this->IRS_getParams = (IRS_getParams_Func)dlsym(libHandle, "IRS_getParams");
        this->IRS_control = (IRS_control_Func)dlsym(libHandle, "IRS_control");
        this->IRS_decodeMsg = (IRS_decodeMsg_Func)dlsym(libHandle, "IRS_decodeMsg");

        this->isLoaded = true;
    };
    bool isLoaded = false;
};

// FIXME:此处使用单例是因为使用静态函数方法实现的回调函数，在生成多个对象时，回调函数的调用会有问题；使用单例不太合适，之后记得修改
MFIriStarDriver *MFIriStarDriver::getInstance()
{
    static QMutex mutex;
    static QScopedPointer<MFIriStarDriver> pInst;
    if (Q_UNLIKELY(!pInst))
    {
        QMutexLocker locker(&mutex);
        if (pInst.isNull())
        {
            pInst.reset(new MFIriStarDriver());
        }
    }
    return pInst.data();
}

MFIriStarDriver::MFIriStarDriver(QObject *parent) : BDriver{parent}
{
    m_driverLib = QSharedPointer<IriStarDriverLib>(new IriStarDriverLib);
    m_idVendor = IRISTAR_ID_VENDOR;
    m_idProduct = IRISTAR_ID_PRODUCT;

    connect(this, &MFIriStarDriver::addFeature, this, &MFIriStarDriver::onStartEnroll);
    connect(this, &MFIriStarDriver::featureExist, this, [this](const QString &featureID)
            {
                //重复录入
                if(deviceStatus() != DEVICE_STATUS_DOING_ENROLL)
                {
                    return;
                } 
                if(m_algorithmType == ALGORITHM_TYPE_IRIS)
                {
                    Q_EMIT enrollProcess(ENROLL_PROCESS_REPEATED_ENROLL,DEVICE_TYPE_Iris,featureID);
                }
                else 
                {
                    Q_EMIT enrollProcess(ENROLL_PROCESS_REPEATED_ENROLL,DEVICE_TYPE_Face,featureID);
                } });
}

MFIriStarDriver::~MFIriStarDriver()
{
    if (m_driverLib->isLoaded && m_irsHandle)
    {
        bool enable = false;
        m_driverLib->IRS_control(m_irsHandle, IRS_CONTROL_IRIS_LIGHT, &enable, sizeof(enable));
        m_driverLib->IRS_control(m_irsHandle, IRS_CONTROL_CANCEL_OPR, NULL, 0);  // 停止当前正在进行的流程
        m_driverLib->IRS_releaseInstance(m_irsHandle);    
    }

    if (m_libHandle)
    {
        dlclose(m_libHandle);
        m_libHandle = NULL;
    }

    m_driverLib.clear();
}

bool MFIriStarDriver::initDriver()
{
    if (!loadLib())
    {
        return false;
    }

    if (!initDeviceHandle())
    {
        return false;
    }

    // FIXME:由于是使用静态方法实现，但生成多个类的实例对象时，第一个对象的c_func指针会被第二个对象的c_func指针覆盖
    Callback<void(IRS_Results *)>::func = std::bind(&MFIriStarDriver::resultCallback, this, std::placeholders::_1);
    void (*c_func)(IRS_Results *) = static_cast<decltype(c_func)>(Callback<void(IRS_Results *)>::callback);

    // 设置结果回调函数
    int retVal = m_driverLib->IRS_control(m_irsHandle,
                                          IRS_CONTROL_SET_RESULT_CALLBACK,
                                          (void *)c_func,
                                          sizeof(void *));

    if (retVal)
    {
        KLOG_DEBUG() << "Set result callback failed, retVal:" << retVal;
        return false;
    }

    // 设置图像回调函数
    retVal = m_driverLib->IRS_control(m_irsHandle, IRS_CONTROL_SET_IMAGE_CALLBACK, (void *)imageCallback, sizeof(void *));
    if (retVal)
    {
        KLOG_DEBUG() << "Set image callback failed, retVal:" << retVal;
        return false;
    }

    // 为避免启动之前设备异常，进行一次关闭流程和状态灯操作
    reset();

    m_isInitialized = true;
    return true;
}

/**
 * FIXME:
 * 如果用户_1的权限下，运行程序创建实例，然后正常退出;再在用户_2的环境下运行程序创建实例
 * 则会报错存在多个实例 Multiple instance found. Only one instance is allowed at a time.
 * 原因在于首次创建实例时，会创建/tmp/SIRDEV.lck文件，用来绑定用户信息。
 * 删除/tmp/SIRDEV.lck文件，用户_2则可以创建实例。
 * 也就是说这个设备只能被一个用户使用。
 */

bool MFIriStarDriver::initDeviceHandle()
{
    const char *sdkConfigFile = IRIS_IS_STARTUP_CONFIG_PATH;
    // sdk-linux-init根据配置文件中的名称定义
    const char *startUpConfigs[2] = {sdkConfigFile, "sdk-linux-init"};
    char logPath[256] = "/var/log/iris-log/1.log";

    /**
     * IRS_createInstance 创建设备句柄，每次打开设备时必须先调用
     * IRS_PARAM_SET_STARTUP_CONFIGURATION_FILE 设置配置文件路径，必须先设置
     * IRS_PARAM_SET_LOG_PATH SDK 存放日志文件全路径
     * IRS_PARAM_NONE 参数结束标识
     */

    int retVal = m_driverLib->IRS_createInstance(&m_irsHandle,
                                                 IRS_PARAM_SET_STARTUP_CONFIGURATION_FILE, (void *)startUpConfigs, 2,
                                                 IRS_PARAM_SET_LOG_PATH, logPath, sizeof(logPath),
                                                 IRS_PARAM_NONE);
    if (retVal != 0)
    {
        KLOG_DEBUG() << "Create instance failed, retVal:" << retVal;
        return false;
    }
    KLOG_DEBUG() << "Create instance success";

    // 获取设备类型，根据设备类型读取配置文件内容
    retVal = m_driverLib->IRS_getParams(m_irsHandle,
                                        IRS_PARAM_GET_DEVICE_TYPE, m_devType, sizeof(m_devType),
                                        IRS_PARAM_NONE);

    if (retVal != 0)
    {
        KLOG_DEBUG() << "Get device type failed, retVal:" << retVal;
        return false;
    }
    KLOG_DEBUG() << "Get device type : " << QString(m_devType);

    // 设置SDK需要的其他配置信息，从配置文件中读取
    char buf[96] = {0};
    snprintf(buf, sizeof(buf), "sdk-%s", m_devType);
    const char *cfgSections[] = {"sdk-common", buf};
    retVal = m_driverLib->IRS_setParamsByConfigFile(m_irsHandle, sdkConfigFile, &cfgSections[0], 2);
    if (retVal != 0)
    {
        KLOG_DEBUG() << "Set param by config file failed, retVal:" << retVal;
        return false;
    }

    return true;
}

bool MFIriStarDriver::loadLib()
{
    // 打开指定的动态链接库文件；立刻决定返回前接触所有未决定的符号。若打开错误返回NULL，成功则返回库引用
    m_libHandle = dlopen(IRIS_IS_DRIVER_LIB, RTLD_NOW);
    if (m_libHandle == NULL)
    {
        KLOG_ERROR() << "Load libirs_sdk2.so failed,error:" << dlerror();
        return false;
    }
    m_driverLib->loadSym(m_libHandle);

    return true;
}

void MFIriStarDriver::reset()
{
    stop();
}

/**
 * 注册模式：F-人脸 I-双眼 l-单左眼 r-单右眼
 * 识别模式：F-人脸 I-双眼
 * 识别虹膜时不区分单双眼，只传双眼即可；只有W200设备支持注册时选择单双眼，其他设备全部是双眼
 */
void MFIriStarDriver::doingEnrollStart(DeviceType deviceType)
{
    if (deviceType == DEVICE_TYPE_Iris)
    {
        m_algorithmType = ALGORITHM_TYPE_IRIS;
    }
    else if (deviceType == DEVICE_TYPE_Face)
    {
        m_algorithmType = ALGORITHM_TYPE_FACE;
    }
    m_currentDeviceType = deviceType;

    setVideoStream(m_algorithmType.c_str());
    setDeviceStatus(DEVICE_STATUS_DOING_ENROLL);

    // 开启注册流程，用于获取人脸/虹膜注册特征信息和图像，非阻塞调用。结果数据通过结果回调函数irsResultCallback返回
    // 采集数据的特征类型，只支持I/F，其中I表示虹膜，F表示人脸
    int retVal = prepareEnroll(m_algorithmType.c_str());
}

void MFIriStarDriver::doingIdentifyStart(DeviceType deviceType, QStringList featureIDs)
{
    if (deviceType == DEVICE_TYPE_Iris)
    {
        m_algorithmType = ALGORITHM_TYPE_IRIS;
    }
    else if (deviceType == DEVICE_TYPE_Face)
    {
        m_algorithmType = ALGORITHM_TYPE_FACE;
    }
    m_currentDeviceType = deviceType;

    setVideoStream(m_algorithmType.c_str());
    setDeviceStatus(DEVICE_STATUS_DOING_IDENTIFY);

    int retVal = startIdentify(featureIDs);

    if (retVal != GENERAL_RESULT_OK)
    {
        KLOG_DEBUG() << "Start identify failed. type:" << m_algorithmType.c_str()
                     << "retVal:" << retVal;
        if (deviceStatus() == DEVICE_STATUS_DOING_IDENTIFY)
        {
            if (m_algorithmType == ALGORITHM_TYPE_IRIS)
            {
                Q_EMIT identifyProcess(IDENTIFY_PROCESS_ACQUIRE_FEATURE_FAIL, DEVICE_TYPE_Iris);
            }
            else
            {
                Q_EMIT identifyProcess(IDENTIFY_PROCESS_ACQUIRE_FEATURE_FAIL, DEVICE_TYPE_Face);
            }
        }
    }
}

void MFIriStarDriver::stop()
{
    bool enable = false;
    int retVal = m_driverLib->IRS_control(m_irsHandle, IRS_CONTROL_IRIS_LIGHT, &enable, sizeof(enable));
    retVal = m_driverLib->IRS_control(m_irsHandle, IRS_CONTROL_CANCEL_OPR, NULL, 0);  // 停止当前正在进行的流程
    KLOG_DEBUG() << QString("Stop the current process %1,retVal:%2").arg(0 == retVal ? "success" : "failed").arg(retVal);
    setDeviceStatus(DEVICE_STATUS_IDLE);
    m_algorithmType.clear();
    m_identifyFeatureCache.clear();
    m_currentDeviceType = -1;
}

void MFIriStarDriver::setDeviceInfo(const QString &idVendor, const QString &idProduct)
{
    m_idVendor = idVendor;
    m_idProduct = idProduct;
}

int MFIriStarDriver::prepareEnroll(const char *objectType)
{
    KLOG_DEBUG() << "prepareEnroll";
    // 注册前需要开启识别流程判断之前是否注册过
    int retVal = startIdentify(QStringList());
    if (retVal == -1)
    {
        KLOG_DEBUG() << "add Feature";
        Q_EMIT addFeature();
    }
    return retVal;
}

int MFIriStarDriver::startIdentify(QStringList featureIDs)
{
    KLOG_DEBUG() << "startIdentify";
    // TODO:这段代码有多处使用，可以提炼复用
    QList<QByteArray> saveList;
    QString featureID;

    if (featureIDs.isEmpty())
    {
        saveList = FeatureDB::getInstance()->getFeatures(m_idVendor, m_idProduct, (DeviceType)m_currentDeviceType);
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

    if (saveList.count() == 0)
    {
        KLOG_DEBUG() << " no features in the database";
        return -1;
    }

    int retVal = 0;
    m_identifyFeatureCache = saveList;
    // 识别类型，只支持I/F，其中I表示虹膜，F表示人脸
    if (m_algorithmType == ALGORITHM_TYPE_IRIS)
    {
        retVal = identifyIris(saveList);
    }
    else if (m_algorithmType == ALGORITHM_TYPE_FACE)
    {
        retVal = identifyFace(saveList);
    }

    return retVal;
}

int MFIriStarDriver::identifyIris(QList<QByteArray> features)
{
    IRS_IrisFeatureArray irisFeature;  // 虹膜特征
    irisFeature.sizeInBytes = sizeof(IRS_IrisFeatureArray);
    irisFeature.numFeatures = features.count();
    irisFeature.featureSize = IRIS_FEATURE_LEN;

    QByteArray allSavedFeature;
    Q_FOREACH (auto feature, features)
    {
        allSavedFeature.append(feature);
    }
    irisFeature.featureData = (void *)allSavedFeature.data();

    int retVal = m_driverLib->IRS_setParams(m_irsHandle, IRS_PARAM_SET_IRIS_FEATURE_ARRAY_V2, &irisFeature, sizeof(irisFeature), IRS_PARAM_NONE);

    // 开始识别流程，非阻塞调用
    retVal = m_driverLib->IRS_control(m_irsHandle, IRS_CONTROL_START_RECO, (void *)m_algorithmType.c_str(), strlen(m_algorithmType.c_str()));
    KLOG_DEBUG() << "start identify iris:" << retVal;
    return retVal;
}

int MFIriStarDriver::identifyFace(QList<QByteArray> features)
{
    IRS_FeatureArray faceFeature;
    faceFeature.sizeInBytes = sizeof(IRS_FeatureArray);
    faceFeature.numFeatures = features.count();
    faceFeature.featureSize = FACE_FEATURE_LEN;

    QByteArray allFaceFeature;
    Q_FOREACH (auto feature, features)
    {
        allFaceFeature.append(feature);
    }
    faceFeature.featureData = (void *)allFaceFeature.data();

    // 设置人脸特征信息
    int retVal = m_driverLib->IRS_setParams(m_irsHandle, IRS_PARAM_SET_FACE_FEATURE_ARRAY, &faceFeature, sizeof(faceFeature), IRS_PARAM_NONE);

    int setTimeOut;
    if (deviceStatus() == DEVICE_STATUS_DOING_ENROLL)
    {
        // 录入流程中识别人脸是否重复录入过，超时时间为5秒
        setTimeOut = 5000;
        m_driverLib->IRS_setParams(m_irsHandle, IRS_PARAM_SET_FACE_RECOGNIZE_TIMEOUT_VALUE, &setTimeOut, sizeof(setTimeOut), IRS_PARAM_NONE);
    }
    else if (deviceStatus() == DEVICE_STATUS_DOING_IDENTIFY)
    {
        // 识别流程中人脸识别超时默认是30秒
        setTimeOut = 300000;
        m_driverLib->IRS_getParams(m_irsHandle, IRS_PARAM_GET_FACE_RECOGNIZE_TIMEOUT_VALUE, &setTimeOut, sizeof(setTimeOut), IRS_PARAM_NONE);
    }

    int getTimeout;
    m_driverLib->IRS_getParams(m_irsHandle, IRS_PARAM_GET_FACE_RECOGNIZE_TIMEOUT_VALUE, &getTimeout, sizeof(getTimeout), IRS_PARAM_NONE);
    KLOG_DEBUG() << "get Time out:" << getTimeout;

    // 开始识别流程，非阻塞调用
    retVal = m_driverLib->IRS_control(m_irsHandle, IRS_CONTROL_START_RECO, (void *)m_algorithmType.c_str(), strlen(m_algorithmType.c_str()));
    KLOG_DEBUG() << "start identify face:" << retVal;
    return retVal;
}

void MFIriStarDriver::onStartEnroll()
{
    KLOG_DEBUG() << "on start Enroll";
    KLOG_DEBUG() << "deviceStatus:" << deviceStatus();
    /**
     * FIXME:人脸识别结束后，马上进行人脸的录入，会录入失败，错误码：IRS2_ERROR_INVALID_STATE
     * 为避免录入流程失败，停止当前正在进行的流程
     */
    int retVal = m_driverLib->IRS_control(m_irsHandle, IRS_CONTROL_CANCEL_OPR, NULL, 0);

    if (deviceStatus() != DEVICE_STATUS_DOING_ENROLL)
    {
        return;
    }

    retVal = m_driverLib->IRS_control(m_irsHandle, IRS_CONTROL_START_ENROLL, (void *)m_algorithmType.c_str(), strlen(m_algorithmType.c_str()));
    KLOG_DEBUG() << "IRS_CONTROL_START_ENROLL:" << retVal;
    if (retVal != GENERAL_RESULT_OK)
    {
        KLOG_ERROR() << "start enroll failed:" << retVal;
        DeviceType deviceType;
        (m_algorithmType == ALGORITHM_TYPE_IRIS) ? deviceType = DEVICE_TYPE_Iris : deviceType = DEVICE_TYPE_Face;
        Q_EMIT enrollProcess(ENROLL_PROCESS_ACQUIRE_FEATURE_FAIL, deviceType);
    }
}

void MFIriStarDriver::resultCallback(IRS_Results *results)
{
    IRS_MSG2_TYPE msg2 = m_driverLib->IRS_decodeMsg(m_irsHandle, results);
    KLOG_DEBUG() << "resultCallback msg2:" << msg2;
    switch (msg2)
    {
    // 注册成功时有可能返回以下3个消息。双眼注册时，有可能会返回单眼注册成功的消息，
    // 即左眼注册成功会先返回左眼注册成功消息，右眼注册成功会先返回右眼注册成功消息，需要统一判断是否全部注册成功。
    case IRS_MSG2_LEFT_IRIS_ENROLLED:  // 左眼注册成功
    {
        KLOG_DEBUG() << "Left iris enrolled";
        handleIrisEnrolled(results);
        break;
    }
    case IRS_MSG2_RIGHT_IRIS_ENROLLED:  // 右眼注册成功
    {
        KLOG_DEBUG() << "Right iris enrolled";
        handleIrisEnrolled(results);
        break;
    }
    case IRS_MSG2_DOUBLE_IRISES_ENROLLED:  // 双眼注册成功
    {
        KLOG_DEBUG() << "double irises enrolled";
        handleIrisEnrolled(results);
        break;
    }
    case IRS_MSG2_FACE_ENROLLED:  // 人脸注册成功消息
    {
        handleFaceEnrolled(results);
        break;
    }
    case IRS_MSG2_LEFT_IRIS_RECOGNIZED:  // 左眼识别成功消息
    {
        KLOG_DEBUG() << "left iris recognized";
        handleRecognized(results);
        break;
    }
    case IRS_MSG2_RIGHT_IRIS_RECOGNIZED:  // 右眼识别成功消息
    {
        KLOG_DEBUG() << "right iris recognized";
        handleRecognized(results);
        break;
    }
    case IRS_MSG2_FACE_RECOGNIZED:  // 人脸识别成功消息
    {
        handleRecognized(results);
        break;
    }
    case IRS_MSG2_IRIS_ENROLLING_FAILED:        // 双眼虹膜注册失败消息
    case IRS_MSG2_LEFT_IRIS_ENROLLING_FAILED:   // 左眼虹膜注册失败消息
    case IRS_MSG2_RIGHT_IRIS_ENROLLING_FAILED:  // 右眼虹膜注册失败消息
    case IRS_MSG2_FACE_ENROLLING_FAILED:        // 人脸注册失败消息
    {
        KLOG_DEBUG() << " acquiring  failed :" << msg2;
        handleEnrollingFailed(results);
        break;
    }
    case IRS_MSG2_DISTANCE_UPDATED:
    {
        KLOG_DEBUG() << "results->currentDistance:" << results->currentDistance;
        break;
    }
    case IRS_MSG2_IRIS_RECOGNIZING_FAILED:  // 虹膜识别失败消息
    {
        handleRecognizingFailed(results);
        break;
    }
    case IRS_MSG2_FACE_RECOGNIZING_FAILED:
    {
        handleRecognizingFailed(results);
        break;
    }
    default:
        break;
    }
}

/**
 * NOTE:虹膜双眼注册时，有可能会返回单眼注册成功的消息，
 * 即左眼注册成功会先返回左眼注册成功消息，右眼注册成功会先返回右眼注册成功消息，需要统一判断是否全部注册成功。
 */
void MFIriStarDriver::handleIrisEnrolled(IRS_Results *results)
{
    if ((0 < results->leftEyeData.image.dataLen) && (results->leftEyeData.image.data != nullptr))
    {
        m_leftEyeFeatureCache = QByteArray((char *)results->leftEyeData.featureData, results->leftEyeData.featureDataLen);
        KLOG_DEBUG() << "Left Eye Feature Cache:" << m_leftEyeFeatureCache;
    }

    if ((0 < results->rightEyeData.image.dataLen) && (results->rightEyeData.image.data != nullptr))
    {
        m_rightEyeFeatureCache = QByteArray((char *)results->rightEyeData.featureData, results->rightEyeData.featureDataLen);
        KLOG_DEBUG() << "Right Eye Feature Cache:" << m_rightEyeFeatureCache;
    }

    if (m_leftEyeFeatureCache.isEmpty() || m_rightEyeFeatureCache.isEmpty())
    {
        return;
    }

    QByteArray featureByteArray;
    featureByteArray.append(m_leftEyeFeatureCache);
    featureByteArray.append(m_rightEyeFeatureCache);
    KLOG_DEBUG() << "feature enrolled:" << featureByteArray;

    QString featureID = QCryptographicHash::hash(featureByteArray, QCryptographicHash::Md5).toHex();
    DeviceInfo deviceInfo;
    deviceInfo.idVendor = m_idVendor;
    deviceInfo.idProduct = m_idProduct;
    DeviceType devType;

    FeatureDB::getInstance()->addFeature(featureID, featureByteArray, deviceInfo, (DeviceType)m_currentDeviceType);
    KLOG_DEBUG() << "featureID:" << featureID;

    Q_EMIT enrollProcess(ENROLL_PROCESS_SUCCESS, DEVICE_TYPE_Iris, featureID);

    m_leftEyeFeatureCache.clear();
    m_rightEyeFeatureCache.clear();
}

void MFIriStarDriver::handleEnrollingFailed(IRS_Results *results)
{
    KLOG_DEBUG() << "Acquire or Enroll failed, type:" << m_algorithmType.c_str();
    if (m_algorithmType == ALGORITHM_TYPE_IRIS)
    {
        Q_EMIT enrollProcess(ENROLL_PROCESS_ACQUIRE_FEATURE_FAIL, DEVICE_TYPE_Iris);
    }
    else
    {
        Q_EMIT enrollProcess(ENROLL_PROCESS_ACQUIRE_FEATURE_FAIL, DEVICE_TYPE_Face);
    }
}

void MFIriStarDriver::handleRecognized(IRS_Results *results)
{
    KLOG_DEBUG() << QString("%1 Recognized Matched Score:").arg((m_algorithmType == ALGORITHM_TYPE_IRIS) ? "Iris" : "Face")
                 << results->matchedScore
                 << "Matched Index:" << results->matchedIndex;

    auto feature = m_identifyFeatureCache.value(results->matchedIndex);
    QString featureID = FeatureDB::getInstance()->getFeatureID(feature);

    if (deviceStatus() == DEVICE_STATUS_DOING_ENROLL)
    {
        Q_EMIT this->featureExist(featureID);
    }
    else
    {
        
        if (m_algorithmType == ALGORITHM_TYPE_IRIS)
        {
            Q_EMIT identifyProcess(IDENTIFY_PROCESS_MACTCH, DEVICE_TYPE_Iris, featureID);
        }
        else if (m_algorithmType == ALGORITHM_TYPE_FACE)
        {
            Q_EMIT identifyProcess(IDENTIFY_PROCESS_MACTCH, DEVICE_TYPE_Face, featureID);
        }
    }
}

void MFIriStarDriver::handleRecognizingFailed(IRS_Results *results)
{
    KLOG_DEBUG() << QString("%1 identify failed").arg((m_algorithmType == ALGORITHM_TYPE_IRIS) ? "Iris" : "Face");

    if (deviceStatus() == DEVICE_STATUS_DOING_ENROLL)
    {
        Q_EMIT this->addFeature();
    }
    else
    {
        if (m_algorithmType == ALGORITHM_TYPE_IRIS)
        {
            Q_EMIT identifyProcess(IDENTIFY_PROCESS_NO_MATCH, DEVICE_TYPE_Iris);
        }
        else if (m_algorithmType == ALGORITHM_TYPE_FACE)
        {
            Q_EMIT identifyProcess(IDENTIFY_PROCESS_NO_MATCH, DEVICE_TYPE_Face);
        }
    }
}

void MFIriStarDriver::handleFaceEnrolled(IRS_Results *results)
{
    if (results->faceData.image.dataLen <= 0 || !(results->faceData.image.data))
    {
        Q_EMIT enrollProcess(ENROLL_PROCESS_ACQUIRE_FEATURE_FAIL,DEVICE_TYPE_Face);
        return;
    }
    QByteArray faceFeature((char *)results->faceData.featureData, results->faceData.featureDataLen);
    KLOG_DEBUG() << "faceFeature:" << faceFeature;

    QString featureID = QCryptographicHash::hash(faceFeature, QCryptographicHash::Md5).toHex();
    DeviceInfo deviceInfo;
    deviceInfo.idVendor = m_idVendor;
    deviceInfo.idProduct = m_idProduct;
    bool isSaved = FeatureDB::getInstance()->addFeature(featureID, faceFeature, deviceInfo, (DeviceType)m_currentDeviceType);
    KLOG_DEBUG() << "m_isSaved:" << isSaved;
    KLOG_DEBUG() << "face enrolled,featureID" << featureID;

    Q_EMIT enrollProcess(ENROLL_PROCESS_SUCCESS, DEVICE_TYPE_Face, featureID);
}

void MFIriStarDriver::imageCallback(IRS_Image *irsImage)
{
}

/**
 * @brief 设置工作时显示的实时视频流
 * @param const char *object 实时流类型，只支持I/F，其中I表示虹膜，F表示人脸
 */
int MFIriStarDriver::setVideoStream(const char *object)
{
    char type[3] = {0};

    if (0 == memcmp("S108", m_devType, strlen(m_devType)) && ('I' == *object))
    {  // 双目测距设备(S108/M300L)在SDK内部均为S108,虹膜流程时要显示实时流需要设置为IF
        KLOG_DEBUG() << "setVideoStream, IF";
        memcpy(type, "IF", strlen("IF"));
    }
    else
    {
        KLOG_DEBUG() << "setVideoStream, object:" << QString(object);
        memcpy(type, object, sizeof(*object));
    }
    return m_driverLib->IRS_setParams(m_irsHandle, IRS_PARAM_SET_VIDEO_STREAMING, (void *)type, strlen(type), IRS_PARAM_NONE);
}

}  // namespace Kiran
