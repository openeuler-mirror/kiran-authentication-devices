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

#include "fp-zk-driver.h"
#include <dlfcn.h>
#include <qt5-log-i.h>
#include "auth-enum.h"
#include "driver/driver-factory.h"
#include "zkfp.h"

namespace Kiran
{
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

struct FPZKDriverLib
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

    void loadSym(HANDLE libHandle)
    {
        this->ZKFPM_Init = (T_ZKFPM_Init)dlsym(libHandle, "ZKFPM_Init");
        this->ZKFPM_Terminate = (T_ZKFPM_Terminate)dlsym(libHandle, "ZKFPM_Terminate");
        this->ZKFPM_GetDeviceCount = (T_ZKFPM_GetDeviceCount)dlsym(libHandle, "ZKFPM_GetDeviceCount");
        this->ZKFPM_OpenDevice = (T_ZKFPM_OpenDevice)dlsym(libHandle, "ZKFPM_OpenDevice");
        this->ZKFPM_CloseDevice = (T_ZKFPM_CloseDevice)dlsym(libHandle, "ZKFPM_CloseDevice");
        this->ZKFPM_SetParameters = (T_ZKFPM_SetParameters)dlsym(libHandle, "ZKFPM_SetParameters");
        this->ZKFPM_GetParameters = (T_ZKFPM_GetParameters)dlsym(libHandle, "ZKFPM_GetParameters");
        this->ZKFPM_AcquireFingerprint = (T_ZKFPM_AcquireFingerprint)dlsym(libHandle, "ZKFPM_AcquireFingerprint");
        this->ZKFPM_DBInit = (T_ZKFPM_DBInit)dlsym(libHandle, "ZKFPM_DBInit");
        this->ZKFPM_DBFree = (T_ZKFPM_DBFree)dlsym(libHandle, "ZKFPM_DBFree");
        this->ZKFPM_DBMerge = (T_ZKFPM_DBMerge)dlsym(libHandle, "ZKFPM_DBMerge");
        this->ZKFPM_DBDel = (T_ZKFPM_DBDel)dlsym(libHandle, "ZKFPM_DBDel");
        this->ZKFPM_DBAdd = (T_ZKFPM_DBAdd)dlsym(libHandle, "ZKFPM_DBAdd");
        this->ZKFPM_DBClear = (T_ZKFPM_DBClear)dlsym(libHandle, "ZKFPM_DBClear");
        this->ZKFPM_DBCount = (T_ZKFPM_DBCount)dlsym(libHandle, "ZKFPM_DBCount");
        this->ZKFPM_DBIdentify = (T_ZKFPM_DBIdentify)dlsym(libHandle, "ZKFPM_DBIdentify");
        this->ZKFPM_DBMatch = (T_ZKFPM_DBMatch)dlsym(libHandle, "ZKFPM_DBMatch");
        this->ZKFPM_SetLogLevel = (T_ZKFPM_SetLogLevel)dlsym(libHandle, "ZKFPM_SetLogLevel");
        this->ZKFPM_ConfigLog = (T_ZKFPM_ConfigLog)dlsym(libHandle, "ZKFPM_ConfigLog");

        this->isLoaded = true;
    };
    bool isLoaded = false;
};

REGISTER_DRIVER(FINGERPRINT_ZK_DRIVER_NAME, FPZKDriver);

FPZKDriver::FPZKDriver(QObject* parent) : Driver(parent),
                                          m_libHandle(nullptr)
{
    m_driverLib.reset(new FPZKDriverLib);
    setName(FINGERPRINT_ZK_DRIVER_NAME);
}

FPZKDriver::~FPZKDriver()
{
    if (m_libHandle)
    {
        dlclose(m_libHandle);
        m_libHandle = NULL;
    }
}

bool FPZKDriver::initDriver(const QString& libPath)
{
    QString loadLibPath;
    libPath.isEmpty() ? (loadLibPath = FP_ZK_DRIVER_LIB) : (loadLibPath = libPath);
    return loadLibrary(FP_ZK_DRIVER_LIB);
}

bool FPZKDriver::loadLibrary(const QString& libPath)
{
    // 打开指定的动态链接库文件；立刻决定返回前接触所有未决定的符号。若打开错误返回NULL，成功则返回库引用
    m_libHandle = dlopen(libPath.toStdString().c_str(), RTLD_NOW);
    if (m_libHandle == nullptr)
    {
        KLOG_ERROR() << "Load libzkfp failed,error:" << dlerror();

        return false;
    }

    m_driverLib->loadSym(m_libHandle);
    return true;
}

bool FPZKDriver::isLoaded()
{
    return m_driverLib->isLoaded;
}

int FPZKDriver::ZKFPM_Init()
{
    return m_driverLib->ZKFPM_Init();
}

int FPZKDriver::ZKFPM_Terminate()
{
    return m_driverLib->ZKFPM_Terminate();
}

int FPZKDriver::ZKFPM_GetDeviceCount()
{
    return m_driverLib->ZKFPM_GetDeviceCount();
}

HANDLE FPZKDriver::ZKFPM_OpenDevice(int index)
{
    return m_driverLib->ZKFPM_OpenDevice(index);
}

int FPZKDriver::ZKFPM_CloseDevice(HANDLE hDevice)
{
    return m_driverLib->ZKFPM_CloseDevice(hDevice);
}

int FPZKDriver::ZKFPM_SetParameters(HANDLE hDevice, int nParamCode, unsigned char* paramValue, unsigned int cbParamValue)
{
    return m_driverLib->ZKFPM_SetParameters(hDevice, nParamCode, paramValue, cbParamValue);
}

int FPZKDriver::ZKFPM_GetParameters(HANDLE hDevice, int nParamCode, unsigned char* paramValue, unsigned int* cbParamValue)
{
    return m_driverLib->ZKFPM_GetParameters(hDevice, nParamCode, paramValue, cbParamValue);
}

int FPZKDriver::ZKFPM_AcquireFingerprint(HANDLE hDevice, unsigned char* fpImage, unsigned int cbFPImage, unsigned char* fpTemplate, unsigned int* cbTemplate)
{
    return m_driverLib->ZKFPM_AcquireFingerprint(hDevice, fpImage, cbFPImage, fpTemplate, cbTemplate);
}

int FPZKDriver::ZKFPM_AcquireFingerprintImage(HANDLE hDevice, unsigned char* fpImage, unsigned int cbFPImage)
{
    return m_driverLib->ZKFPM_AcquireFingerprintImage(hDevice, fpImage, cbFPImage);
}

HANDLE FPZKDriver::ZKFPM_DBInit()
{
    return m_driverLib->ZKFPM_DBInit();
}

int FPZKDriver::ZKFPM_DBFree(HANDLE hDBCache)
{
    return m_driverLib->ZKFPM_DBFree(hDBCache);
}

int FPZKDriver::ZKFPM_DBMerge(HANDLE hDBCache, unsigned char* temp1, unsigned char* temp2, unsigned char* temp3, unsigned char* regTemp, unsigned int* cbRegTemp)
{
    return m_driverLib->ZKFPM_DBMerge(hDBCache, temp1, temp2, temp3, regTemp, cbRegTemp);
}

int FPZKDriver::ZKFPM_DBAdd(HANDLE hDBCache, unsigned int fid, unsigned char* fpTemplate, unsigned int cbTemplate)
{
    return m_driverLib->ZKFPM_DBAdd(hDBCache, fid, fpTemplate, cbTemplate);
}

int FPZKDriver::ZKFPM_DBDel(HANDLE hDBCache, unsigned int fid)
{
    return m_driverLib->ZKFPM_DBDel(hDBCache, fid);
}

int FPZKDriver::ZKFPM_DBClear(HANDLE hDBCache)
{
    return m_driverLib->ZKFPM_DBClear(hDBCache);
}

int FPZKDriver::ZKFPM_DBCount(HANDLE hDBCache, unsigned int* fpCount)
{
    return m_driverLib->ZKFPM_DBCount(hDBCache, fpCount);
}

int FPZKDriver::ZKFPM_DBIdentify(HANDLE hDBCache, unsigned char* fpTemplate, unsigned int cbTemplate, unsigned int* FID, unsigned int* score)
{
    return m_driverLib->ZKFPM_DBIdentify(hDBCache, fpTemplate, cbTemplate, FID, score);
}

int FPZKDriver::ZKFPM_DBMatch(HANDLE hDBCache, unsigned char* template1, unsigned int cbTemplate1, unsigned char* template2, unsigned int cbTemplate2)
{
    return m_driverLib->ZKFPM_DBMatch(hDBCache, template1, cbTemplate1, template2, cbTemplate2);
}

int FPZKDriver::ZKFPM_ExtractFromImage(HANDLE hDBCache, const char* lpFilePathName, unsigned int DPI, unsigned char* fpTemplate, unsigned int* cbTemplate)
{
    return m_driverLib->ZKFPM_ExtractFromImage(hDBCache, lpFilePathName, DPI, fpTemplate, cbTemplate);
}

void FPZKDriver::ZKFPM_SetLogLevel(int nLevel)
{
    return m_driverLib->ZKFPM_SetLogLevel(nLevel);
}

void FPZKDriver::ZKFPM_ConfigLog(int nLevel, int nType, char* fileName)
{
    return m_driverLib->ZKFPM_ConfigLog(nLevel, nType, fileName);
}
}  // namespace Kiran
