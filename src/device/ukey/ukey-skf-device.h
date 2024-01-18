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
#include <QSharedPointer>
#include <QTimer>
#include "device/auth-device.h"
#include "driver/ukey/ukey-skf-driver.h"
#include "ukey-skf.h"

namespace Kiran
{
class UKeySKFDevice : public AuthDevice
{
    Q_OBJECT
public:
    explicit UKeySKFDevice(const QString &vid, const QString &pid, DriverPtr driver, QObject *parent = nullptr);
    ~UKeySKFDevice();

    void resetUkey();

private Q_SLOTS:
    bool initSerialNumber();

private:
    bool initDevice() override;
    void doingEnrollStart(const QString &extraInfo) override;
    void doingIdentifyStart(const QString &value) override;

    void deviceStopEnroll() override;
    void deviceStopIdentify() override;

    void identifyKeyFeature(const QString &pin, QByteArray keyFeature);

    void bindingUKey(DEVHANDLE devHandle, const QString &pin);
    ULONG createContainer(const QString &pin, DEVHANDLE devHandle, HAPPLICATION *appHandle, HCONTAINER *containerHandle);

    bool isExistsApplication(DEVHANDLE devHandle, const QString &appName);
    bool isExistBinding();

    void notifyUKeyEnrollProcess(EnrollProcess process, ULONG error = SAR_OK, const QString &featureID = QString());
    void notifyUKeyIdentifyProcess(IdentifyProcess process, ULONG error = SAR_OK, const QString &featureID = QString());

    QString getPinErrorReson(ULONG error);

private:
    ULONG m_retryCount = 10;
    UKeySKFDriver *m_driver = nullptr;
    static QStringList m_existingSerialNumber;
    QTimer m_reInitSerialNumberTimer;
    QString m_driverLibPath;
};

}  // namespace Kiran
