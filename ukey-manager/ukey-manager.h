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

#include "ukey-skf.h"

namespace Kiran
{
class UKeySKFDriver;
class UkeyManager
{
public:
    UkeyManager();
    ~UkeyManager();

    bool initDriver();

    ULONG resetUkey();
    ULONG changePin(const QString &userType, const QString &currentPin, const QString &newPin, ULONG *retryCount);

    /**
     * @brief 解锁PIN
     * @param[in] adminPin   管理员PIN码
     * @param[in] userPin 新的用户PIN码
     * @param[in,out] retryCount PIN错误剩余次数
     * @return 错误码
     */
    ULONG unblockPin(const QString &adminPin, const QString &userPin, ULONG *retryCount);

    QString getErrorReason(ULONG error);

private:
    UKeySKFDriver *m_driver;
    DEVHANDLE m_devHandle;
    HAPPLICATION m_appHandle;
    HCONTAINER m_containerHandle;
    ULONG m_retryCount = 1000000;
};
}  // namespace Kiran
