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
#include "kiran-auth-device-i.h"
#include <QString>

namespace Kiran
{
#define ZK_ID_VENDOR "1b55"
#define SD_ID_VENDOR "05e3"
#define FT_ID_VENDOR "096e"

static const struct ThirdPartyDeviceSupported
{
    //设备类型，必填
    DeviceType deviceType;
    //生产商ID，必填
    QString idVendor;
    //产品ID，必填
    QString idProduct;
    //驱动路径，选填
    QString driverPath;
    //描述信息，选填
    QString description;
}ThirdPartyDeviceSupportedTable[] = {
    {DEVICE_TYPE_FingerPrint,"1b55","0120","","ZK"},
    {DEVICE_TYPE_FingerVein,"05e3","0608","","SD"},
    {DEVICE_TYPE_UKey,"096e","0309","","FT"}
};

}