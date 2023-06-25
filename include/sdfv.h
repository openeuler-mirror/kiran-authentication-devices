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

namespace Kiran
{
#define SD_FV_TEMPLATE_NUM 6                                   // 注册登记模板时，需要采集的指静脉次数
#define SD_ENROLL_TIME_OUT 300                                 /* 入录指静脉等待时间，单位秒*/
#define SD_TEMPLATE_MAX_NUMBER 10000                           /* 最大指纹模板数目 */

#define IMAGE_TIME_OUT 50                                      // 获取图像等待的时间,单位秒（即：超过这个时间没有检测到touch就返回）,经过简单测试该设备最大等待时间为50s
#define IMAGE_ROI_WIDTH 500                                    // 图像宽度
#define IMAGE_ROI_HEIGHT 200                                   // 图像高度
#define IMAGE_SIZE (IMAGE_ROI_WIDTH * IMAGE_ROI_HEIGHT + 208)  // 图片大小

#define FEATURE_SIZE 1024                                      // 指静脉特征值大小
#define TEMPLATE_SIZE 6144                                     // 指静脉模板大小

#define TEMPLATE_FV_NUM 6                                      // 注册登记模板时，需要采集的指静脉次数

#define SD_FV_DRIVER_LIB "sdfv"                                // 该名称不是实际so名称，由于实际驱动由多个so组成，为了表示方便自定义了一个名称进行标识
#define SD_FV_DRIVER_LIB_PROCESS "libTGFVProcessAPI.so"
#define SD_FV_DRIVER_LIB_COM "libTGVM661JComAPI.so"
#define SD_LICENSE_PATH "/usr/share/kiran-authentication-devices-sdk/sd/license.dat"

#define VOICE_BI 0x00              // Bi
#define VOICE_BIBI 0x01            // BiBi
#define VOICE_REG_SUCCESS 0x02     // 登记成功
#define VOICE_REG_FAIL 0x03        // 登记失败
#define VOICE_PLS_REPUT 0x04       // 请再放一次
#define VOICE_PLS_PUT_CRUCLY 0x05  // 请正确放入手指
#define VOICE_PLS_PUT_SOFTLY 0x06  // 请自然轻放手指
#define VOICE_IDENT_SUCCESS 0x07   // 验证成功
#define VOICE_IDENT_FAIL 0x08      // 验证失败
#define VOICE_PLS_REDO 0x09        // 请重试
#define VOICE_DEL_SUCCESS 0x0A     // 删除成功
#define VOICE_DEL_FAIL 0x0B        // 删除失败
#define VOICE_VEIN_FULL 0x0C       // 指静脉已满
#define VOICE_REREG 0x0D           // 登记重复
#define VOICE_VOLUME0 0xF0         // 静音
#define VOICE_VOLUME1 0xF2         // 音量级别1
#define VOICE_VOLUME2 0xF4         // 音量级别2
#define VOICE_VOLUME3 0xF6         // 音量级别3
#define VOICE_VOLUME4 0xF8         // 音量级别4
#define VOICE_VOLUME5 0xFA         // 音量级别5
#define VOICE_VOLUME6 0xFC         // 音量级别6
#define VOICE_VOLUME7 0xFE         // 音量级别7
}  // namespace Kiran
