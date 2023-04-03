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

#include <QMap>
#include <QObject>

namespace Kiran
{
class AuthDevice;
class Context : public QObject
{
    Q_OBJECT
public:
    explicit Context(QObject *parent = nullptr);

    QString getName();
    virtual AuthDevice *createDevice(const QString &idVendor, const QString &idProduct);
    virtual QList<AuthDevice *> getDevices() { return m_deviceMap.values(); };
    QString getSoPath() { return m_soPath; };

protected:
    QString m_soPath;
    QMap<QString, AuthDevice *> m_deviceMap;
    AuthDevice *m_device;
};

}  // namespace Kiran