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
#include <QFutureWatcher>
#include "device/bio-device.h"
#include <QSharedPointer>

namespace Kiran
{
enum ExtractFeatureMode
{
    EXTRACT_FEATURE_REGISTER,  // 提取的特征录入时使用
    EXTRACT_FEATURE_VERIFY     // 提取的特征验证时使用
};

struct DriverLib;
class FVSDDevice : public BioDevice
{
    Q_OBJECT
public:
    explicit FVSDDevice(QObject *parent = nullptr);
    ~FVSDDevice();

    bool initDevice() override;
    BDriver *getDriver() override;

private:
    bool loadLib();

    void enrollTemplateMerge();
    void saveEnrollTemplateToCache(QByteArray enrollTemplate) override;

    QByteArray acquireFeature() override;
    void acquireFeatureStop() override;
    void acquireFeatureFail() override;

    void enrollProcessRetry() override;

    QString isFeatureEnrolled(QByteArray fpTemplate) override;

    QString identifyFeature(QByteArray feature, QStringList featureIDs) override;

    QByteArray getFeatureFromImage(QByteArray image, ExtractFeatureMode mode);

    int mergeTemplateCount() override;
    int templateMatch(QByteArray fpTemplate1, QByteArray fpTemplate2) override;
    void notifyEnrollProcess(EnrollProcess process, const QString &featureID = QString()) override;
    void notifyIdentifyProcess(IdentifyProcess process, const QString &featureID = QString()) override;

private:
    QSharedPointer<DriverLib> m_driverLib;

    Handle m_libProcessHandle;
    Handle m_libComHandle;
};

}  // namespace Kiran
