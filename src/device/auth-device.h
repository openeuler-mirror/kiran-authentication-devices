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

#include <QDBusContext>
#include <QDBusObjectPath>
#include <QDBusServiceWatcher>
#include <QFutureWatcher>
#include <QObject>
#include "auth-enum.h"
#include "kiran-auth-device-i.h"
#include <QSharedPointer>

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
    virtual BDriver *getDriver() = 0;

    QDBusObjectPath getObjectPath() { return m_objectPath; };
    QString deviceID() { return m_deviceID; };
    QString deviceDriver() { return m_deviceDriver; };
    int deviceType() { return m_deviceType; };
    int deviceStatus() { return m_deviceStatus; }
    QString deviceName() { return m_deviceName; };
    DeviceInfo deviceInfo();

    void setDeviceType(DeviceType deviceType);
    void setDeviceStatus(DeviceStatus deviceStatus);
    void setDeviceName(const QString &deviceName);
    void setDeviceInfo(const QString &idVendor, const QString &idProduct);
    void setDeviceDriver(const QString &deviceDriver);

public Q_SLOTS:
    virtual void EnrollStart(const QString &extraInfo);
    virtual void EnrollStop();
    virtual void IdentifyStart(const QString &value);
    virtual void IdentifyStop();
    virtual QStringList GetFeatureIDList();

protected:
    virtual QByteArray acquireFeature() = 0;
    virtual void acquireFeatureStop() = 0;
    virtual void acquireFeatureFail() = 0;

private Q_SLOTS:
    void onNameLost(const QString &serviceName);
    void handleAcquiredFeature();
    void handleRetry();

protected:
    void clearWatchedServices();
    virtual void internalStopEnroll();
    virtual void internalStopIdentify();

private:
    void registerDBusObject();
    void initServiceWatcher();
    void initFutureWatcher();

    void onEnrollStart(const QDBusMessage &message, const QString &extraInfo);
    void onEnrollStop(const QDBusMessage &message);
    void onBioEnrollStart(const QDBusMessage &dbusMessage);
    void onUKeyEnrollStart(const QDBusMessage &dbusMessage, QJsonValue jsonValue);

    void onIdentifyStart(const QDBusMessage &message, const QString &value);
    void onIdentifyStop(const QDBusMessage &message);
    void onBioIdentifyStart(const QDBusMessage &dbusMessage);
    void onUKeyIdentifyStart(const QDBusMessage &dbusMessage, QJsonValue jsonValue);

    virtual void doingEnrollProcess(QByteArray feature){};
    virtual void doingIdentifyProcess(QByteArray feature){};

    virtual void doingUKeyEnrollStart(const QString &pin, bool rebinding = false){};
    virtual void doingUKeyIdentifyStart(const QString &pin){};

Q_SIGNALS:
    void retry();

protected:
    QString m_deviceDriver;
    QSharedPointer<AuthDeviceAdaptor> m_dbusAdaptor;
    bool m_doAcquire = true;
    QStringList m_identifyIDs;
    QByteArrayList m_enrollTemplates;
    QSharedPointer<QFutureWatcher<QByteArray>> m_futureWatcher;
    QString m_pin;

private:
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
