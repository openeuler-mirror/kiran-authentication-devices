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

#include <libudev.h>
#include <QDBusObjectPath>
#include <QObject>
#include <QSocketNotifier>
#include <QTimer>
#include "auth-enum.h"
#include <QDBusContext>

class AuthDeviceManagerAdaptor;

namespace Kiran
{
class AuthDevice;
class ContextFactory;

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
    void handleSocketNotifierRead(int socket);
    void handleDeviceAdded(const DeviceInfo &usbInfo);
    void handleDeviceDeleted();
    void handleDeviceReCreate();
    void handleDeviceCreateFail(DeviceInfo deviceInfo);

private:
    void init();
    void initDeviceMonitor(struct udev *udev);
    QList<DeviceInfo> enumerateDevices(struct udev *udev);
    void processDevice(struct udev_device *dev);
    void deviceSimpleInfo(struct udev_device *dev);

    void onRemove(const QDBusMessage &message,const QString &feature_id);
    void onSetEnableDriver(const QDBusMessage &message,const QString &driver_name, bool enable);

Q_SIGNALS:
    void DeviceAdded(int device_type, const QString &device_id);
    void DeviceDeleted(int device_type, const QString &device_id);

private:
    static AuthDeviceManager *m_instance;
    struct udev *m_udev;
    struct udev_monitor *m_monitor;

    int m_fd;
    AuthDeviceManagerAdaptor *m_dbusAdaptor;
    QSocketNotifier *m_socketNotifierRead;
    // 总线 -- AuthDevice对象对应
    QMap<QString, AuthDevice *> m_deviceMap;
    ContextFactory *m_contextFactory;

    QTimer *m_timer;

    // 设备信息-重试次数
    QMap<DeviceInfo,int> m_retreyCreateDeviceMap;
};
}  // namespace Kiran
