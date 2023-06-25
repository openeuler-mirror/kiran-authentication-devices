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
#include "ukey-skf.h"
#include "driver/driver.h"

namespace Kiran
{
struct SKFDriverLib;

class UKeySKFDriver : public Driver
{
    Q_OBJECT
public:
    UKeySKFDriver(QObject *parent = nullptr);
    ~UKeySKFDriver();

    bool initDriver(const QString &libPath = QString()) override;
    bool loadLibrary(const QString &libPath) override;
    bool isLoaded() override;
    
    QStringList enumDevName();
    QStringList enumDevSerialNumber();
    DEVHANDLE connectDev();

    DEVHANDLE connectDev(const QString &serialNumber);

    void deleteAllApplication(DEVHANDLE devHandle);
    QString enumApplication(DEVHANDLE devHandle);
    bool isExistPublicKey(HCONTAINER containerHandle);

    ULONG devAuth(DEVHANDLE devHandle);
    ULONG onOpenApplication(DEVHANDLE hDev, LPSTR szAppName, HAPPLICATION *appHandle);
    ULONG onOpenContainer(HAPPLICATION appHandle, const QString &pin, QString containerName, ULONG *retryCount, HCONTAINER *containerHandle);

    void closeApplication(HAPPLICATION appHandle);
    void closeContainer(HCONTAINER containerHandle);
    void disConnectDev(DEVHANDLE devHandle);

    ULONG createApplication(DEVHANDLE devHandle, QString pin, QString appName, HAPPLICATION *appHandle);
    ULONG createContainer(HAPPLICATION appHandle, QString pin, QString containerName, ULONG *retryCount, HCONTAINER *containerHandle);

    ULONG genECCKeyPair(HCONTAINER containerHandle, ECCPUBLICKEYBLOB *pBlob);

    ULONG authSignData(HCONTAINER containerHandle, DEVHANDLE devHandle, ECCSIGNATUREBLOB &Signature);
    ULONG verifyData(DEVHANDLE devHandle, ECCSIGNATUREBLOB &Signature, ECCPUBLICKEYBLOB *publicKey);

    ULONG changePin(DEVHANDLE devHandle, int userType, const QString &currentPin, const QString &newPin, ULONG *retryCount);
    
    ULONG unblockPin(DEVHANDLE devHandle, const QString &adminPin, const QString &newUserPin, ULONG *retryCount);

    ULONG resetUkey(DEVHANDLE devHandle);

    QString getErrorReason(ULONG error);

    QString getDefaultValueFromConf(const QString &key);


private:
    QSharedPointer<SKFDriverLib> m_driverLib;
    HANDLE m_libHandle;
};

}  // namespace Kiran