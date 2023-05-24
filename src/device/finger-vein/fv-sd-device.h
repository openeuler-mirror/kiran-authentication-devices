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
#include "device/bio-device.h"

namespace Kiran
{
enum ExtractFeatureMode
{
    EXTRACT_FEATURE_REGISTER,  // 提取的特征录入时使用
    EXTRACT_FEATURE_VERIFY     // 提取的特征验证时使用
};

struct FVSDDriverLib;
class FVSDDevice : public BioDevice
{
    Q_OBJECT
public:
    explicit FVSDDevice(QObject *parent = nullptr);
    ~FVSDDevice();
    bool initDriver() override;

private:
    bool loadLib();

    QByteArray acquireFeature() override;
    void acquireFeatureStop() override;
    void acquireFeatureFail() override;

    int enrollTemplateMatch(QByteArray fpTemplate1, QByteArray fpTemplate2) override;
    void enrollTemplateMerge() override;
    void saveEnrollTemplateToCache(QByteArray enrollTemplate) override;
    void enrollProcessRetry() override;

    QString isFeatureEnrolled(QByteArray fpTemplate) override;
    QString identifyFeature(QByteArray feature, QStringList featureIDs) override;

    void notifyEnrollProcess(EnrollProcess process, const QString &featureID = QString()) override;
    void notifyIdentifyProcess(IdentifyProcess process, const QString &featureID = QString()) override;

    QByteArray getFeatureFromImage(QByteArray image, ExtractFeatureMode mode);

private:
    QSharedPointer<FVSDDriverLib> m_driverLib;
    Handle m_libProcessHandle;
    Handle m_libComHandle;
};

}  // namespace Kiran
