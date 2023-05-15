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

#include <QMap>
#include <QObject>
#include <QSharedPointer> 

namespace Kiran
{
class AuthDevice;
typedef QSharedPointer<AuthDevice> AuthDevicePtr;

class Context : public QObject
{
    Q_OBJECT
public:
    explicit Context(QObject *parent = nullptr);
    virtual AuthDevicePtr createDevice(const QString &idVendor, const QString &idProduct) = 0;
    virtual QList<AuthDevicePtr> getDevices() { return m_deviceMap.values(); };

protected:
    QMap<QString, AuthDevicePtr> m_deviceMap;
    AuthDevicePtr m_device;
};

}  // namespace Kiran
