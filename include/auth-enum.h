/**
 * Copyright (c) 2022 ~ 2023 KylinSec Co., Ltd.
 * kiran-cc-daemon is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *          http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 *
 * Author:     tangjie02 <tangjie02@kylinos.com.cn>
 */

#pragma once
#include <QString>

namespace Kiran
{

#define FPRINT_DIR "/etc/kiran-authentication-devices/fingerprint"
#define FACE_DIR "/etc/kiran-authentication-devices/face"
#define DATABASE_DIR "/usr/share/kiran-authentication-devices"
#define DRIVER_BLACK_LIST_CONF "/etc/kiran-authentication-device/driver-blacklist.conf"
#define DRIVERS_CONF "/etc/kiran-authentication-devices/drivers.conf"

#define AUTH_USER_ADMIN "com.kylinsec.kiran.authentication.user-administration"

struct DeviceInfo
{
    QString idVendor;
    QString idProduct;
    QString busPath;

    bool operator<(const DeviceInfo& dev) const
    {
        if (this->idVendor.compare(dev.idVendor) < 0)
            return true;
        else if (this->idVendor.compare(dev.idVendor) > 0)
            return false;

        if (this->idProduct.compare(dev.idProduct) < 0)
            return true;
        else if (this->idProduct.compare(dev.idProduct) > 0)
            return false;

        if (this->busPath.compare(dev.busPath) < 0)
            return true;
        else if (this->busPath.compare(dev.busPath) > 0)
            return false;

        return false;
    };
};

enum GeneralResult
{
    GENERAL_RESULT_UNSUPPORT = -1,        // 此接口不支持
    GENERAL_RESULT_OK = 0,                // 成功
    GENERAL_RESULT_FAIL = 1,              // 失败
    GENERAL_RESULT_TIMEOUT = 2,           // 超时
    GENERAL_RESULT_NO_FOUND_DEVICE = 3,   // 设备不存在
    GENERAL_RESULT_OPEN_DEVICE_FAIL = 4,  // 打开设备失败
};

// 录入过程
enum EnrollProcess
{
    // 获取特征失败
    ENROLL_PROCESS_ACQUIRE_FEATURE_FAIL,
    // 录入阶段性完成
    ENROLL_PROCESS_PASS,
    // 重复录入同一特征
    ENROLL_PROCESS_REPEATED_ENROLL,
    // 录入时前后录入的不是同一个特征（例如：不是同一根手指/同一个人脸）
    ENROLL_PROCESS_INCONSISTENT_FEATURE,
    // 特征融合失败
    ENROLL_PROCESS_MEGER_FAIL,
    // 录入成功
    ENROLL_PROCESS_SUCCESS,
    // 特征保存失败
    ENROLL_PROCESS_SAVE_FAIL,
    // 合成后的指纹与先前录入的指纹不匹配
    ENROLL_PROCESS_INCONSISTENT_FEATURE_AFTER_MERGED,
};

enum IdentifyProcess
{
    // 验证超时
    IDENTIFY_PROCESS_TIME_OUT,
    // 获取特征失败
    IDENTIFY_PROCESS_ACQUIRE_FEATURE_FAIL,
    // 匹配
    IDENTIFY_PROCESS_MACTCH,
    // 不匹配
    IDENTIFY_PROCESS_NO_MATCH,
    // PIN码不正确
    IDENTIFY_PROCESS_PIN_INCORRECT
};

}  // namespace Kiran