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
#define FP_TEMPLATE_MAX_NUMBER 10000 /* 最大指纹模板数目 */
#define FP_TIME_OUT 600000           /* 一次等待指纹时间，单位毫秒*/
#define FP_MAX_TRY_COUNT 10          /* 最大尝试次数 */

#define FP_ZK_PARAM_CODE_VID_PID 1015
#define FP_ZK_PARAM_CODE_VENDOR_NAME 1101
#define FP_ZK_PARAM_CODE_PRODUCT_NAME 1102
#define FP_ZK_PARAM_CODE_SERIAL_NUNBER 1103
#define FP_ZK_MAX_TEMPLATE_SIZE 2048 /*模板最大长度 */

#define FP_ZK_DRIVER_LIB "libzkfp.so"
#define FP_ZK_MEGER_TEMPLATE_COUNT 3

#define ZKFP_ERR_ALREADY_INIT 1        /*已经初始化 */
#define ZKFP_ERR_OK 0                  /*操作成功 */
#define ZKFP_ERR_INITLIB -1            /*初始化算法库失败 */
#define ZKFP_ERR_INIT -2               /*初始化采集库失败 */
#define ZKFP_ERR_NO_DEVICE -3          /*无设备连接 */
#define ZKFP_ERR_NOT_SUPPORT -4        /*接口暂不支持 */
#define ZKFP_ERR_INVALID_PARAM -5      /*无效参数 */
#define ZKFP_ERR_OPEN -6               /*打开设备失败 */
#define ZKFP_ERR_INVALID_HANDLE -7     /*无效句柄 */
#define ZKFP_ERR_CAPTURE -8            /*取像失败 */
#define ZKFP_ERR_EXTRACT_FP -9         /*提取指纹模板失败 */
#define ZKFP_ERR_ABSORT -10            /*中断 */
#define ZKFP_ERR_MEMORY_NOT_ENOUGH -11 /*内存不足 */
#define ZKFP_ERR_BUSY -12              /*当前正在采集 */
#define ZKFP_ERR_ADD_FINGER -13        /*添加指纹模板失败 */
#define ZKFP_ERR_DEL_FINGER -14        /*删除指纹失败 */
#define ZKFP_ERR_FAIL -17              /*操作失败 */
#define ZKFP_ERR_CANCEL -18            /*取消采集 */
#define ZKFP_ERR_VERIFY_FP -20         /*比对指纹失败 */
#define ZKFP_ERR_MERGE -22             /*合并登记指纹模板失败	*/
#define ZKFP_ERR_NOT_OPENED -23;       /*设备未打开	*/
#define ZKFP_ERR_NOT_INIT -24;         /*未初始化	*/
#define ZKFP_ERR_ALREADY_OPENED -25;   /*设备已打开	*/
#define ZKFP_ERR_LOADIMAGE -26         /*文件打开失败			*/
#define ZKFP_ERR_ANALYSE_IMG -27       /*处理图像失败			*/
#define ZKFP_ERR_TIMEOUT -28           /*超时					*/
}  // namespace Kiran
