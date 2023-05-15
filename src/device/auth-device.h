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

#include <QDBusContext>
#include <QDBusObjectPath>
#include <QDBusServiceWatcher>
#include <QFutureWatcher>
#include <QObject>
#include <QSharedPointer>
#include "auth-enum.h"
#include "kiran-auth-device-i.h"

class AuthDeviceAdaptor;

namespace Kiran
{
typedef void *Handle;
class BDriver;

class AuthDevice : public QObject, protected QDBusContext
{
    Q_OBJECT
    Q_PROPERTY(QString DeviceID READ deviceID CONSTANT)
    Q_PROPERTY(QString DeviceDriver READ deviceDriver CONSTANT)
    Q_PROPERTY(int DeviceType READ deviceType)
    Q_PROPERTY(int DeviceStatus READ deviceStatus)

public:
    explicit AuthDevice(QObject *parent = nullptr);
    virtual ~AuthDevice();
    bool init();
    virtual bool initDevice() = 0;

    QDBusObjectPath getObjectPath() { return m_objectPath; };
    QString deviceID() { return m_deviceID; };
    QString deviceDriver() { return m_deviceDriver; };
    int deviceType() { return m_deviceType; };
    int deviceStatus() { return m_deviceStatus; };
    QString deviceName() { return m_deviceName; };
    DeviceInfo deviceInfo();

    void setDeviceType(DeviceType deviceType) { m_deviceType = deviceType; };
    void setDeviceStatus(DeviceStatus deviceStatus) { m_deviceStatus = deviceStatus; };
    void setDeviceName(const QString &deviceName) { m_deviceName = deviceName; };
    void setDeviceInfo(const QString &idVendor, const QString &idProduct);
    void setDeviceDriver(const QString &deviceDriver);

public Q_SLOTS:
    virtual void EnrollStart(const QString &extraInfo);
    virtual void EnrollStop();
    virtual void IdentifyStart(const QString &value);
    virtual void IdentifyStop();
    virtual QStringList GetFeatureIDList();

protected:
    void clearWatchedServices();
    virtual void internalStopEnroll() = 0;
    virtual void internalStopIdentify() = 0;

private:
    void onEnrollStart(const QDBusMessage &message, const QString &extraInfo);
    void onEnrollStop(const QDBusMessage &message);
    void onIdentifyStart(const QDBusMessage &message, const QString &value);
    void onIdentifyStop(const QDBusMessage &message);

    virtual void doingEnrollStart(const QString &extraInfo) = 0;
    virtual void doingIdentifyStart(const QString &value) = 0;

private Q_SLOTS:
    void onNameLost(const QString &serviceName);

private:
    void registerDBusObject();
    void initServiceWatcher();

Q_SIGNALS:
    void retry();

protected:
    QSharedPointer<AuthDeviceAdaptor> m_dbusAdaptor;
    QStringList m_identifyIDs;

private:
    QString m_deviceDriver;
    QString m_deviceID;
    int m_deviceType;
    int m_deviceStatus;
    QString m_deviceName;
    QString m_idVendor;
    QString m_idProduct;
    QDBusObjectPath m_objectPath;
    QSharedPointer<QDBusServiceWatcher> m_serviceWatcher;

    /**
     * 用于注册com.kylinsec.Kiran.AuthDevice.Device服务时的编号
     * 在生成AuthDevice对象，注册dbus服务成功后，数值加1
     * FIXME:由于设备拔出时num不会减少，num不断增加，有可能达到最大值，从而出现问题
     */
    static size_t m_deviceObjectNum;
};
}  // namespace Kiran
