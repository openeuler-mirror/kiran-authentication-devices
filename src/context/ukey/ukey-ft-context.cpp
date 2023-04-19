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

#include "ukey-ft-context.h"
#include <qt5-log-i.h>
#include "device/ukey/ukey-ft-device.h"
#include "utils.h"

namespace Kiran
{
UKeyFTContext::UKeyFTContext(QObject* parent)
    : Context{parent}
{
}

AuthDevice* UKeyFTContext::createDevice(const QString& idVendor, const QString& idProduct)
{
    auto ftDevice = new UKeyFTDevice();
    if (!Utils::driverEnabled(ftDevice->deviceDriver()))
    {
        KLOG_INFO() << QString("driver %1 is disabled! device %2:%3 can't be used")
                           .arg(ftDevice->deviceDriver())
                           .arg(idVendor)
                           .arg(idProduct);
        return nullptr;
    }
    if (ftDevice->init())
    {
        QString deviceName = Utils::getDeviceName(idVendor, idProduct);
        if (deviceName.isEmpty())
        {
            deviceName = "Feitian Technologies";
        }
        ftDevice->setDeviceName(deviceName);
        ftDevice->setDeviceInfo(idVendor, idProduct);
        m_deviceMap.insert(ftDevice->deviceID(), ftDevice);
        return ftDevice;
    }
    else
    {
        KLOG_ERROR() << QString("device %1:%2 init failed!").arg(idVendor).arg(idProduct);
        ftDevice->deleteLater();
        return nullptr;
    }
}
}  // namespace Kiran
