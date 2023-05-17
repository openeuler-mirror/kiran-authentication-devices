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

#pragma once
#include <stdint.h>
#include "device/auth-device.h"
#include "driver/ukey/ukey-skf-driver.h"
#include "ukey-skf.h"
#include <QSharedPointer>

namespace Kiran
{
class UKeyFTDevice : public AuthDevice
{
    Q_OBJECT
public:
    explicit UKeyFTDevice(QObject *parent = nullptr);
    ~UKeyFTDevice();

    bool initDriver() override;

private:
    void doingEnrollStart(const QString &extraInfo) override;
    void doingIdentifyStart(const QString &value) override;
    
    void internalStopEnroll() override;
    void internalStopIdentify() override;

    void identifyKeyFeature(QByteArray keyFeature);
    
    void bindingUKey();
    ECCPUBLICKEYBLOB genKeyPair();
    bool isExistPublicKey();
    bool isExistsApplication(const QString &appName);

    void notifyUKeyEnrollProcess(EnrollProcess process, ULONG error = SAR_OK, const QString &featureID = QString());
    void notifyUKeyIdentifyProcess(IdentifyProcess process, ULONG error = SAR_OK, const QString &featureID = QString());

private:
    DEVHANDLE m_devHandle;
    HAPPLICATION m_appHandle;
    HCONTAINER m_containerHandle;
    ULONG m_retryCount = 1000000;
    QString m_pin;
    QSharedPointer<UKeySKFDriver> m_driver;
};

}  // namespace Kiran
