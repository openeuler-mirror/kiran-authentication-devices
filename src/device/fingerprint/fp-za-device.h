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

#include <QFutureWatcher>
#include <QSharedPointer>
#include "auth-enum.h"
#include "device/bio-device.h"

namespace Kiran
{
class FPZADriver;

class FPZADevice : public BioDevice
{    
    Q_OBJECT
public:
    explicit FPZADevice(const QString& vid, const QString& pid, DriverPtr driver, QObject* parent = nullptr);
    ~FPZADevice();

private:
    bool initDevice() override;
    QByteArray acquireFeature() override;
    // 停止采集指纹模板
    void acquireFeatureStop() override;
    void acquireFeatureFail() override;
    void templateMerge() override;

    void notifyEnrollProcess(EnrollProcess process, const QString& featureID = QString()) override;
    void notifyIdentifyProcess(IdentifyProcess process, const QString& featureID = QString()) override;

    // 对比两枚指纹是否匹配
    int templateMatch(QByteArray fpTemplate1, QByteArray fpTemplate2) override;

    QString identifyFeature(QByteArray fpTemplate, QList<QByteArray> existedfeatures) override;

    int openBioDevice() override;

private:
    QSharedPointer<FPZADriver> m_driver;
};
}  // namespace Kiran
