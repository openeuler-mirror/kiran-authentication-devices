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

#include "fv-sd-context.h"
#include <qt5-log-i.h>
#include "context/context-factory.h"
#include "device/finger-vein/fv-sd-device.h"
#include "third-party-device.h"
#include "utils.h"

namespace Kiran
{
REGISTER_CONTEXT(FVSDContext);
FVSDContext::FVSDContext(QObject* parent)
    : Context{parent}
{
}

// TODO:createDevice 流程类似，考虑优化，减少重复代码
//  fp-zk-context 需要管理多个so，可以生成不同 so的设备
AuthDevicePtr FVSDContext::createDevice(const QString& idVendor, const QString& idProduct)
{
    if (idVendor != SD_ID_VENDOR)
    {
        return nullptr;
    }

    auto sdDevice = QSharedPointer<FVSDDevice>(new FVSDDevice());
    if (!Utils::driverEnabled(sdDevice->deviceDriver()))
    {
        KLOG_INFO() << QString("driver %1 is disabled! device %2:%3 can't be used")
                           .arg(sdDevice->deviceDriver())
                           .arg(idVendor)
                           .arg(idProduct);
        return nullptr;
    }
    if (!sdDevice->init())
    {
        KLOG_ERROR() << QString("device %1:%2 init failed!").arg(idVendor).arg(idProduct);
        sdDevice->deleteLater();
        return nullptr;
    }

    QString deviceName = Utils::getDeviceName(idVendor, idProduct);
    if (deviceName.isEmpty())
    {
        deviceName = "SAINT DEEM";
    }
    sdDevice->setDeviceName(deviceName);
    sdDevice->setDeviceInfo(idVendor, idProduct);
    return sdDevice;
}
}  // namespace Kiran
