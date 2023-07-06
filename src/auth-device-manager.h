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

#include <libudev.h>
#include <QDBusContext>
#include <QDBusObjectPath>
#include <QObject>
#include <QSharedPointer>
#include <QSocketNotifier>
#include <QTimer>
#include "auth-enum.h"
#include "udev-monitor.h"

class AuthDeviceManagerAdaptor;

namespace Kiran
{
class AuthDevice;

class AuthDeviceManager : public QObject, protected QDBusContext
{
    Q_OBJECT

public:
    explicit AuthDeviceManager(QObject *parent = nullptr);
    virtual ~AuthDeviceManager();

    static AuthDeviceManager *getInstance() { return m_instance; };
    static void globalInit();
    static void globalDeint() { delete m_instance; };

public Q_SLOTS:
    QString GetDevices();
    QString GetDevicesByType(int device_type);
    QDBusObjectPath GetDevice(const QString &device_id);
    QStringList GetAllFeatureIDs();
    QString GetDriversByType(int device_type);
    void SetEnableDriver(const QString &driver_name, bool enable);
    void Remove(const QString &feature_id);

private Q_SLOTS:
    void handleDeviceAdded(const DeviceInfo &deviceInfo);
    void handleDeviceDeleted();
    void handleDeviceReCreate();
    void handleDeviceCreateFail(DeviceInfo deviceInfo);

private:
    void init();
    void onRemove(const QDBusMessage &message, const QString &feature_id);
    void onSetEnableDriver(const QDBusMessage &message, const QString &driver_name, bool enable);
    QList<QSharedPointer<AuthDevice>> createDevices(const DeviceInfo &deviceInfo);

private:
    static AuthDeviceManager *m_instance;
    QSharedPointer<UdevMonitor> m_udevMonitor;
    QSharedPointer<AuthDeviceManagerAdaptor> m_dbusAdaptor;
    // 总线 -- AuthDevice对象对应
    QMultiMap<QString, QSharedPointer<AuthDevice>> m_deviceMap;
    QTimer m_ReCreateTimer;

    // 设备信息-重试次数
    QMap<DeviceInfo, int> m_retreyCreateDeviceMap;
};
}  // namespace Kiran
