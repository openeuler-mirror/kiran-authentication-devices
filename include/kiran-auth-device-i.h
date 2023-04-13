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

#ifdef __cplusplus
extern "C"
{
#endif

#define AUTH_DEVICE_DBUS_NAME "com.kylinsec.Kiran.AuthDevice"
#define AUTH_DEVICE_DBUS_OBJECT_PATH "/com/kylinsec/Kiran/AuthDevice"
#define AUTH_DEVICE_DBUS_INTERFACE_NAME "com.kylinsec.Kiran.AuthDevice"

#define GENERAL_AUTH_DEVICE_DBUS_OBJECT_PATH "/com/kylinsec/Kiran/AuthDevice/Device"
#define GENERAL_AUTH_DEVICE_DBUS_INTERFACE_NAME "com.kylinsec.Kiran.AuthDevice.Device"

#define AUTH_DEVICE_JSON_KEY_UKEY "ukey"
#define AUTH_DEVICE_JSON_KEY_PIN "pin"
#define AUTH_DEVICE_JSON_KEY_REBINDING "rebinding"
#define AUTH_DEVICE_JSON_KEY_FEATURE_IDS "feature_ids"

    // 录入结果
    enum EnrollResult
    {
        // 录入完成
        ENROLL_RESULT_COMPLETE,
        // 录入失败
        ENROLL_RESULT_FAIL,
        // 录入阶段性完成
        ENROLL_RESULT_PASS,
        // 因为扫描质量或者用户扫描过程中发生的问题引起
        ENROLL_RESULT_RETRY,
        // UKey已经存在绑定关系
        ENROLL_RESULT_UKEY_EXIST_BINDING
    };

    // 识别结果
    enum IdentifyResult
    {
        // 认证失败
        IDENTIFY_RESULT_NOT_MATCH,
        // 认证成功
        IDENTIFY_RESULT_MATCH,
        // 因为扫描质量或者用户扫描过程中发生的问题导致认证不成功
        IDENTIFY_RESULT_RETRY,
    };

    // 设备类型
    enum DeviceType
    {
        DEVICE_TYPE_FingerPrint,  // 指纹
        DEVICE_TYPE_Face,         // 人脸
        DEVICE_TYPE_FingerVein,   // 指静脉
        DEVICE_TYPE_Iris,         // 虹膜
        DEVICE_TYPE_VoicePrint,   // 声纹
        DEVICE_TYPE_UKey,         // ukey
    };

    // 设备状态
    enum DeviceStatus
    {
        DEVICE_STATUS_ERROR,           // 设备发生错误
        DEVICE_STATUS_BUSY,            // 设备忙碌
        DEVICE_STATUS_IDLE,            // 设备空闲
        DEVICE_STATUS_DOING_ENROLL,    // 设备正在录入中
        DEVICE_STATUS_DOING_VERIFY,    // 设备正在验证中
        DEVICE_STATUS_DOING_IDENTIFY,  // 设备正在识别中
        DEVICE_STATUS_DISABLE,         // 设备被禁用
    };

#ifdef __cplusplus
}
#endif
