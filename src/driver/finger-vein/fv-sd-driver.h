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
struct FVSDDriverLib;
typedef void *Handle;

class FVSDDriver : public Driver
{
    Q_OBJECT
public:
    FVSDDriver(QObject *parent = nullptr);
    ~FVSDDriver();

    bool initDriver(const QString &libPath = QString()) override;
    bool loadLibrary(const QString &libPath) override;
    bool isLoaded() override;

    int TGInitFVProcess(const char *licenseDatPath);
    int TGImgExtractFeatureVerify(unsigned char *encryptImg, int imgWidth, int imgHeight, unsigned char *feature);
    int TGFeaturesFusionTmpl(unsigned char *features, int featureSize, unsigned char *tmpl);
    int TGFeatureMatchTmpl1N(unsigned char *feature, unsigned char *matchTmplStart, int matchTmplNum, int *matchIndex, int *matchScore, unsigned char *updateTmpl);
    int TGImgExtractFeatureRegister(unsigned char *encryptImg, int imgWidth, int imgHeight, unsigned char *feature);

    int TGOpenDev(int *mode);
    int TGGetDevStatus();
    int TGCloseDev();
    int TGGetDevFW(char *fw);
    int TGGetDevSN(char *sn);
    int TGPlayDevVoice(int voiceValue);
    int TGGetDevImage(unsigned char *imageData, int timeout);
    int TGCancelGetImage();
    int TGSetDevLed(int ledBlue, int ledGreen, int ledRed);

private:
    QScopedPointer<FVSDDriverLib> m_driverLib;

    Handle m_libProcessHandle;
    Handle m_libComHandle;
};
}  // namespace Kiran
