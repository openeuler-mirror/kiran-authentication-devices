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
#pragma once

#include <QScopedPointer>
#include "driver/driver.h"

namespace Kiran
{
typedef void* HANDLE;
struct FPZKDriverLib;

class FPZKDriver : public Driver
{
    Q_OBJECT
public:
    FPZKDriver(QObject* parent = nullptr);
    ~FPZKDriver();

    bool initDriver(const QString &libPath = QString()) override;
    bool loadLibrary(const QString& libPath) override;
    bool isLoaded() override;

    int ZKFPM_Init();
    int ZKFPM_Terminate();
    int ZKFPM_GetDeviceCount();
    HANDLE ZKFPM_OpenDevice(int index);
    int ZKFPM_CloseDevice(HANDLE hDevice);
    int ZKFPM_SetParameters(HANDLE hDevice, int nParamCode, unsigned char* paramValue, unsigned int cbParamValue);
    int ZKFPM_GetParameters(HANDLE hDevice, int nParamCode, unsigned char* paramValue, unsigned int* cbParamValue);
    int ZKFPM_AcquireFingerprint(HANDLE hDevice, unsigned char* fpImage, unsigned int cbFPImage, unsigned char* fpTemplate, unsigned int* cbTemplate);
    int ZKFPM_AcquireFingerprintImage(HANDLE hDevice, unsigned char* fpImage, unsigned int cbFPImage);
    HANDLE ZKFPM_DBInit();
    int ZKFPM_DBFree(HANDLE hDBCache);
    int ZKFPM_DBMerge(HANDLE hDBCache, unsigned char* temp1, unsigned char* temp2, unsigned char* temp3, unsigned char* regTemp, unsigned int* cbRegTemp);
    int ZKFPM_DBAdd(HANDLE hDBCache, unsigned int fid, unsigned char* fpTemplate, unsigned int cbTemplate);
    int ZKFPM_DBDel(HANDLE hDBCache, unsigned int fid);
    int ZKFPM_DBClear(HANDLE hDBCache);
    int ZKFPM_DBCount(HANDLE hDBCache, unsigned int* fpCount);
    int ZKFPM_DBIdentify(HANDLE hDBCache, unsigned char* fpTemplate, unsigned int cbTemplate, unsigned int* FID, unsigned int* score);
    int ZKFPM_DBMatch(HANDLE hDBCache, unsigned char* template1, unsigned int cbTemplate1, unsigned char* template2, unsigned int cbTemplate2);
    int ZKFPM_ExtractFromImage(HANDLE hDBCache, const char* lpFilePathName, unsigned int DPI, unsigned char* fpTemplate, unsigned int* cbTemplate);
    void ZKFPM_SetLogLevel(int nLevel);
    void ZKFPM_ConfigLog(int nLevel, int nType, char* fileName);

private:
    QScopedPointer<FPZKDriverLib> m_driverLib;
    HANDLE m_libHandle;
};
}  // namespace Kiran
