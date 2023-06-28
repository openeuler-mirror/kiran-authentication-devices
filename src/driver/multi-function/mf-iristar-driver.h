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

#include <QSharedPointer>
#include <string>
#include "auth-enum.h"
#include "driver/driver.h"
#include "irsdk1.h"
#include "irsdk2.h"
#include "kiran-auth-device-i.h"
#include <functional>

namespace Kiran
{
struct IriStarDriverLib;
typedef void *Handle;

class MFIriStarDriver : public Driver
{
    Q_OBJECT

public:
    explicit MFIriStarDriver(QObject *parent = nullptr);
    ~MFIriStarDriver();

    void ref() { ++m_refCount; };
    void unref() { --m_refCount; };
    int refCount() { return m_refCount; };

    bool initDriver(const QString &libPath = QString()) override;
    bool isInitialized() { return m_isInitialized; };

    void doingEnrollStart(DeviceType deviceType);
    void doingIdentifyStart(DeviceType deviceType, QStringList featureIDs);

    void stop();
    void setDeviceInfo(const QString &idVendor, const QString &idProduct);

    bool loadLibrary(const QString &libPath) override;
    bool isLoaded() override;

private:
    struct IrisFeatureData
    {
        QByteArray leftEyeFeature;
        QByteArray rightEyeFeature;
    };

    bool initDeviceHandle();
    void reset();

    int deviceStatus() { return m_deviceStatus; };
    void setDeviceStatus(DeviceStatus deviceStatus) { m_deviceStatus = deviceStatus; };

    void resultCallback(IRS_Results *results);
    static void imageCallback(IRS_Image *irsImage);
    int setVideoStream(const char *object);

    void handleIrisEnrolled(IRS_Results *results);
    void handleFaceEnrolled(IRS_Results *results);
    void handleEnrollingFailed(IRS_Results *results);

    void handleRecognized(IRS_Results *results);
    void handleRecognizingFailed(IRS_Results *results);

    int prepareEnroll(const char *object);

    int startIdentify(QStringList featureIDs);
    int identifyIris(QList<QByteArray> features);
    int identifyFace(QList<QByteArray> features);

private Q_SLOTS:
    void onStartEnroll();

Q_SIGNALS:
    void addFeature();
    void featureExist(const QString &featureID);

    void enrollProcess(EnrollProcess process, DeviceType deviceType, const QString &featureID = QString());
    void identifyProcess(IdentifyProcess process, DeviceType deviceType, const QString &featureID = QString());

private:
    Handle m_libHandle = nullptr;
    IRS_Handle m_irsHandle = nullptr;

    QSharedPointer<IriStarDriverLib> m_driverLib;
    char m_devType[32] = {0};
    std::function<void(IRS_Results *results)> m_resultCallbackFunc;

    QByteArray m_leftEyeFeatureCache;
    QByteArray m_rightEyeFeatureCache;

    QList<QByteArray> m_identifyFeatureCache;

    // 当前算法类型
    std::string m_algorithmType;
    int m_currentDeviceType = -1;
    int m_deviceStatus;

    QString m_idVendor;
    QString m_idProduct;
    bool m_isInitialized = false;

    int m_refCount = 0;
};

}  // namespace Kiran