/**
 * Copyright (c) 2020 ~ 2023 KylinSec Co., Ltd.
 * kiran-authentication-devices is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 * http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 *
 * Author: luoqing <luoqing@kylinsec.com.cn>
 */
#pragma once

#include <QScopedPointer>
#include "driver/driver.h"

namespace Kiran
{
struct FPZADriverLib;
typedef void* LIB_HANDLE;

class FPZADriver : public Driver
{
    Q_OBJECT
public:
    FPZADriver(QObject* parent = nullptr);
    ~FPZADriver();

    bool initDriver(const QString& libPath = QString()) override;
    bool loadLibrary(const QString& libPath) override;
    bool isLoaded() override;

    int openDevice();
    int closeDevice();

    int acquireFeature(int iBufferID, QByteArray& feature);

    QString error2Str(int nErrCode);

    // 1:1 对两个特征进行匹配
    int matchFeature(QByteArray& feature1,QByteArray& feature2);
    
    // 该函数不需要传入特征参数，直接将缓冲区Buffer1和Buffer2的特征，进行合成
    int templateMerge(QByteArray& mergedTemplate);

private:
    QScopedPointer<FPZADriverLib> m_driverLib;
    LIB_HANDLE m_libHandle;
    LIB_HANDLE m_libMatchHandle;
};
}  // namespace Kiran
