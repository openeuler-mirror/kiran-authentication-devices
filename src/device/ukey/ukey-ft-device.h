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

#pragma once
#include <stdint.h>
#include "device/auth-device.h"
#include "driver/ukey/ukey-skf-driver.h"
#include "ukey-skf.h"
#include <QSharedPointer>

namespace Kiran
{
struct DriverLib;

class UKeyFTDevice : public AuthDevice
{
    Q_OBJECT
public:
    explicit UKeyFTDevice(QObject *parent = nullptr);
    ~UKeyFTDevice();

    bool initDevice() override;
    BDriver *getDriver() override;

private:
    void doingUKeyEnrollStart(const QString &pin, bool rebinding = false) override;
    void doingUKeyIdentifyStart(const QString &pin) override;

    void internalStopEnroll() override;
    void internalStopIdentify() override;

    void identifyKeyFeature(QByteArray keyFeature);

    bool isExistPublicKey();
    void bindingCurrentUser();
    ECCPUBLICKEYBLOB genKeyPair();

    bool isExistsApplication(const QString &appName);

    void notifyUKeyEnrollProcess(EnrollProcess process, ULONG error = SAR_OK, const QString &featureID = QString());
    void notifyUKeyIdentifyProcess(IdentifyProcess process, ULONG error = SAR_OK, const QString &featureID = QString());

    QByteArray acquireFeature() override;
    void acquireFeatureStop() override;
    void acquireFeatureFail() override;

private:
    Handle m_libHandle;
    DEVHANDLE m_devHandle;
    HAPPLICATION m_appHandle;
    HCONTAINER m_containerHandle;
    ULONG m_retryCount = 1000000;

    QSharedPointer<UKeySKFDriver> m_driver;
};

}  // namespace Kiran
