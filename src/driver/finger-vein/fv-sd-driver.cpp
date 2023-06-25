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

#include "fv-sd-driver.h"
#include <dlfcn.h>
#include <qt5-log-i.h>
#include "auth-enum.h"
#include "sdfv.h"
#include "driver/driver-factory.h"

namespace Kiran
{

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

struct FVSDDriverLib
{  // libTGFVProcessAPI.so
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

    void loadSym(Handle libProcessHandle, Handle libComHandle)
    {
        this->TGInitFVProcess = (TGInitFVProcessFunc)dlsym(libProcessHandle, "TGInitFVProcess");
        this->TGImgExtractFeatureVerify = (TGImgExtractFeatureVerifyFunc)dlsym(libProcessHandle, "TGImgExtractFeatureVerify");
        this->TGFeaturesFusionTmpl = (TGFeaturesFusionTmplFunc)dlsym(libProcessHandle, "TGFeaturesFusionTmpl");
        this->TGFeatureMatchTmpl1N = (TGFeatureMatchTmpl1NFunc)dlsym(libProcessHandle, "TGFeatureMatchTmpl1N");
        this->TGImgExtractFeatureRegister = (TGImgExtractFeatureRegisterFunc)dlsym(libProcessHandle, "TGImgExtractFeatureRegister");

        this->TGOpenDev = (TGOpenDevFunc)dlsym(libComHandle, "TGOpenDev");
        this->TGGetDevStatus = (TGGetDevStatusFunc)dlsym(libComHandle, "TGGetDevStatus");
        this->TGCloseDev = (TGCloseDevFunc)dlsym(libComHandle, "TGCloseDev");
        this->TGGetDevFW = (TGGetDevFWFunc)dlsym(libComHandle, "TGGetDevFW");
        this->TGGetDevSN = (TGGetDevSNFunc)dlsym(libComHandle, "TGGetDevSN");
        this->TGPlayDevVoice = (TGPlayDevVoiceFunc)dlsym(libComHandle, "TGPlayDevVoice");
        this->TGGetDevImage = (TGGetDevImageFunc)dlsym(libComHandle, "TGGetDevImage");
        this->TGCancelGetImage = (TGCancelGetImageFunc)dlsym(libComHandle, "TGCancelGetImage");
        this->TGSetDevLed = (TGSetDevLedFunc)dlsym(libComHandle, "TGSetDevLed");

        this->isLoaded = true;
    };
    bool isLoaded = false;
};

REGISTER_DRIVER(FINGER_VEIN_SD_DRIVER_NAME, FVSDDriver);

FVSDDriver::FVSDDriver(QObject *parent) : Driver(parent)
{
    m_driverLib.reset(new FVSDDriverLib);
    setName(FINGER_VEIN_SD_DRIVER_NAME);
}

FVSDDriver::~FVSDDriver()
{
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

bool FVSDDriver::initDriver(const QString &libPath)
{
    QString loadLibPath;
    libPath.isEmpty() ? (loadLibPath = SD_FV_DRIVER_LIB_PROCESS) : (loadLibPath = libPath);
    return loadLibrary(SD_FV_DRIVER_LIB_PROCESS);
}

bool FVSDDriver::loadLibrary(const QString &libPath)
{
    // 打开指定的动态链接库文件；立刻决定返回前接触所有未决定的符号。若打开错误返回NULL，成功则返回库引用
    m_libProcessHandle = dlopen(libPath.toStdString().c_str(), RTLD_NOW);
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

    m_driverLib->loadSym(m_libProcessHandle, m_libComHandle);

    return true;
}

bool FVSDDriver::isLoaded()
{
    return m_driverLib->isLoaded;
}

int FVSDDriver::TGInitFVProcess(const char *licenseDatPath)
{
    return m_driverLib->TGInitFVProcess(licenseDatPath);
}

int FVSDDriver::TGImgExtractFeatureVerify(unsigned char *encryptImg, int imgWidth, int imgHeight, unsigned char *feature)
{
    return m_driverLib->TGImgExtractFeatureVerify(encryptImg, imgWidth, imgHeight, feature);
}

int FVSDDriver::TGFeaturesFusionTmpl(unsigned char *features, int featureSize, unsigned char *tmpl)
{
    return m_driverLib->TGFeaturesFusionTmpl(features, featureSize, tmpl);
}

int FVSDDriver::TGFeatureMatchTmpl1N(unsigned char *feature, unsigned char *matchTmplStart, int matchTmplNum, int *matchIndex, int *matchScore, unsigned char *updateTmpl)
{
    return m_driverLib->TGFeatureMatchTmpl1N(feature, matchTmplStart, matchTmplNum, matchIndex, matchScore, updateTmpl);
}

int FVSDDriver::TGImgExtractFeatureRegister(unsigned char *encryptImg, int imgWidth, int imgHeight, unsigned char *feature)
{
    return m_driverLib->TGImgExtractFeatureRegister(encryptImg, imgWidth, imgHeight, feature);
}

int FVSDDriver::TGOpenDev(int *mode)
{
    return m_driverLib->TGOpenDev(mode);
}

int FVSDDriver::TGGetDevStatus()
{
    return m_driverLib->TGGetDevStatus();
}

int FVSDDriver::TGCloseDev()
{
    return m_driverLib->TGCloseDev();
}

int FVSDDriver::TGGetDevFW(char *fw)
{
    return m_driverLib->TGGetDevFW(fw);
}

int FVSDDriver::TGGetDevSN(char *sn)
{
    return m_driverLib->TGGetDevSN(sn);
}

int FVSDDriver::TGPlayDevVoice(int voiceValue)
{
    return m_driverLib->TGPlayDevVoice(voiceValue);
}

int FVSDDriver::TGGetDevImage(unsigned char *imageData, int timeout)
{
    return m_driverLib->TGGetDevImage(imageData, timeout);
}

int FVSDDriver::TGCancelGetImage()
{
    return m_driverLib->TGCancelGetImage();
}

int FVSDDriver::TGSetDevLed(int ledBlue, int ledGreen, int ledRed)
{
    return m_driverLib->TGSetDevLed(ledBlue, ledGreen, ledRed);
}

}  // namespace Kiran
