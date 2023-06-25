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
#include <QObject>
#include <QSharedPointer>

namespace Kiran
{
class Driver : public QObject
{
public:
    Driver(QObject *parent = nullptr);
    virtual ~Driver();

    QString getName() { return m_driverName; };
    void setName(const QString &driverName) { m_driverName = driverName; };

    virtual bool initDriver(const QString &libPath = QString()) = 0;
    virtual bool loadLibrary(const QString &libPath) = 0;
    virtual bool isLoaded() = 0;

private:
    QString m_driverName;
};

typedef QSharedPointer<Driver> DriverPtr;
}  // namespace Kiran
