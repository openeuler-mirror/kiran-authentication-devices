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
#include "driver/driver.h"
#include "ukey-skf.h"
#include <QSharedPointer>

namespace Kiran
{
struct DriverLib;

class UKeySKFDriver : public BDriver
{
public:
    UKeySKFDriver(QObject *parent = nullptr);
    ~UKeySKFDriver();
    QString getName() override;
    QString getFullName() override;
    quint16 getDriverId() override;

    bool loadLibrary(QString libPath);
    DEVHANDLE connectDev();
    void deleteAllApplication(DEVHANDLE devHandle);
    QString enumApplication(DEVHANDLE devHandle);

    ULONG devAuth(DEVHANDLE devHandle);
    HAPPLICATION onOpenApplication(DEVHANDLE hDev, LPSTR szAppName);
    HCONTAINER onOpenContainer(HAPPLICATION appHandle,const QString &pin,QString containerName,ULONG *retryCount);

    void closeApplication(HAPPLICATION appHandle);
    void closeContainer(HCONTAINER containerHandle);
    void disConnectDev(DEVHANDLE devHandle);

    HAPPLICATION createApplication(DEVHANDLE devHandle,QString pin,QString appName);
    HCONTAINER createContainer(HAPPLICATION appHandle, QString pin,QString  containerName,ULONG *retryCount);

    ULONG genECCKeyPair(HCONTAINER containerHandle,ECCPUBLICKEYBLOB *pBlob);

    ULONG authSignData(HCONTAINER containerHandle,DEVHANDLE devHandle,ECCSIGNATUREBLOB &Signature);
    ULONG verifyData(DEVHANDLE devHandle,ECCSIGNATUREBLOB &Signature, ECCPUBLICKEYBLOB &publicKey);

    QString getErrorReason(ULONG error);

    QString getDefaultValueFromConf(const QString &key);

private:
    QSharedPointer<DriverLib> m_driverLib;
    HANDLE m_libHandle;
};

}  // namespace Kiran