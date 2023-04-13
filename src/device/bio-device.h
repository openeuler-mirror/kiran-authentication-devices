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
#include "auth-device.h"

namespace Kiran
{
class BioDevice : public AuthDevice
{
    Q_OBJECT
public:
    explicit BioDevice(QObject *parent = nullptr);
    ~BioDevice();

protected:
    void doingEnrollProcess(QByteArray feature) override;
    void doingIdentifyProcess(QByteArray feature) override;

    virtual void enrollProcessRetry();

    virtual void enrollTemplateMerge() = 0;
    virtual int templateMatch(QByteArray fpTemplate1, QByteArray fpTemplate2) = 0;
    virtual QString identifyFeature(QByteArray feature, QStringList featureIDs) = 0;

    virtual int mergeTemplateCount() = 0;
    virtual void notifyEnrollProcess(EnrollProcess process, const QString &featureID = QString()) = 0;
    virtual void notifyIdentifyProcess(IdentifyProcess process, const QString &featureID = QString()) = 0;

    QByteArrayList enrollTemplatesFromCache();
    virtual void saveEnrollTemplateToCache(QByteArray enrollTemplate);

private:
    virtual QString isFeatureEnrolled(QByteArray fpTemplate);
};

}  // namespace Kiran
