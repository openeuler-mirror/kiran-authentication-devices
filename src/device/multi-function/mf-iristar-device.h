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
#include <QSharedPointer>
#include "device/bio-device.h"
#include "driver/multi-function/mf-iristar-driver.h"

namespace Kiran
{
class MFIriStarDevice : public AuthDevice
{
    Q_OBJECT
public:
    explicit MFIriStarDevice(const QString &vid, const QString &pid, DriverPtr driver, QObject *parent = nullptr);
    ~MFIriStarDevice();

private:
    bool initDevice() override;
    void doingEnrollStart(const QString &extraInfo) override;
    void doingIdentifyStart(const QString &value) override;
    void deviceStopEnroll() override;
    void deviceStopIdentify() override;

    void notifyEnrollProcess(EnrollProcess process, const QString &featureID = QString());
    void notifyIdentifyProcess(IdentifyProcess process, const QString &featureID = QString());

private Q_SLOTS:
    void onEnrollProcess(EnrollProcess process, DeviceType deviceType, const QString &featureID);
    void onIdentifyProcess(IdentifyProcess process, DeviceType deviceType, const QString &featureID);

private:
    QSharedPointer<MFIriStarDriver> m_driver;
};
}  // namespace Kiran
