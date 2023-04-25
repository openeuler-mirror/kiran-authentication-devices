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

#include <QObject>
#include <QSharedPointer>
#include "context.h"

namespace Kiran
{
class FPZKContext;
class FPBuiltInContext;
class FVSDContext;
class UKeyFTContext;

class ContextFactory : public QObject
{
    Q_OBJECT

private:
    explicit ContextFactory(QObject* parent = nullptr);

public:
    static ContextFactory* instance();
    AuthDevicePtr createDevice(const QString& idVendor, const QString& idProduct);
    QList<AuthDevicePtr> getDevices();

    virtual Context* CreateContext();
    void DestoryContext(Context* context);
    bool isDeviceSupported(const QString& idVendor, const QString& idProduct);

private:
    void init();
    AuthDevicePtr createFingerPrintDevice(const QString& idVendor, const QString& idProduct);
    AuthDevicePtr createFingerVeinDevice(const QString& idVendor, const QString& idProduct);
    AuthDevicePtr createUKeyDevice(const QString& idVendor, const QString& idProduct);

private:
    QStringList m_idVendorList;
    QSharedPointer<FPZKContext> m_fpZKContext;
    QSharedPointer<FPBuiltInContext> m_fpBuiltInContext;
    QSharedPointer<FVSDContext> m_fvSDContext;
    QSharedPointer<UKeyFTContext> m_ukeyFTContext;
};
}  // namespace Kiran
