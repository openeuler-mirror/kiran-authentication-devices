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
#include "auth-device.h"

namespace Kiran
{
class BioDevice : public AuthDevice
{
    Q_OBJECT
public:
    explicit BioDevice(const QString &vid, const QString &pid, DriverPtr driver, QObject *parent = nullptr);
    ~BioDevice();
    int mergeTemplateCount() { return m_mergeTemplateCount; };
    void setMergeTemplateCount(int count) { m_mergeTemplateCount = count; };

protected:
    virtual QByteArray acquireFeature() = 0;
    virtual void acquireFeatureStop() = 0;
    virtual void acquireFeatureFail() = 0;
    virtual QString identifyFeature(QByteArray feature, QList<QByteArray> existedfeatures) = 0;

    virtual void templateMerge(){};
    // 特征/模板一对一匹配
    virtual int templateMatch(QByteArray fpTemplate1, QByteArray fpTemplate2) { return GENERAL_RESULT_OK; };

    virtual void deviceStopEnroll() override;
    virtual void deviceStopIdentify() override;

    virtual void enrollProcessRetry();
    // TODO:优化通知
    virtual void notifyEnrollProcess(EnrollProcess process, const QString &featureID = QString()) = 0;
    virtual void notifyIdentifyProcess(IdentifyProcess process, const QString &featureID = QString()) = 0;

    QByteArrayList enrollTemplatesFromCache();
    virtual void saveEnrollTemplateToCache(QByteArray enrollTemplate);

    // TODO：名称不太合适，需要优化
    virtual int openBioDevice();
    bool saveTemplate(QByteArray &featureTemplate, const QString &featureID);

private Q_SLOTS:
    void handleAcquiredFeature();

private:
    void doingEnrollStart(const QString &extraInfo) override;
    void doingIdentifyStart(const QString &value) override;

    void doingEnrollProcess(QByteArray feature);
    void doingIdentifyProcess(QByteArray feature);

    virtual QString isFeatureEnrolled(QByteArray fpTemplate);
    void initFutureWatcher();
    void handleRetry();

protected:
    bool m_doAcquire = true;
    QByteArrayList m_enrollTemplates;
    QSharedPointer<QFutureWatcher<QByteArray>> m_futureWatcher;

private:
    int m_mergeTemplateCount;
};

}  // namespace Kiran
