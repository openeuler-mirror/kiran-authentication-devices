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

#include "fp-zk-context.h"
#include <qt5-log-i.h>
#include <QSettings>
#include "device/fingerprint/fp-zk-device.h"
#include "utils.h"

namespace Kiran
{
FPZKContext::FPZKContext(QObject* parent)
    : Context{parent}
{
}

// fp-zk-context 需要管理多个so，可以生成不同 so的设备
AuthDevice* FPZKContext::createDevice(const QString& idVendor, const QString& idProduct)
{
    /**
     * NOTE:创建对象后，读取配置文件，判断驱动是否开启，再判断是否初始化该设备
     */
    auto zkDevice = new FPZKDevice();
    if(!Utils::driverEnabled(zkDevice->deviceDriver()))
    {
        KLOG_INFO() << QString("driver %1 is disabled! device %2:%3 can't be used")
                           .arg(zkDevice->deviceDriver())
                           .arg(idVendor)
                           .arg(idProduct);
        return nullptr;
    }

    if (zkDevice->init())
    {
        QString deviceName = Utils::getDeviceName(idVendor, idProduct);
        if(deviceName.isEmpty())
        {
            deviceName = "ZK Teco";
        }
        zkDevice->setDeviceName(deviceName);
        zkDevice->setDeviceInfo(idVendor, idProduct);
        m_deviceMap.insert(zkDevice->deviceID(), zkDevice);
        return zkDevice;
    }
    else
    {
        KLOG_ERROR() << QString("device %1:%2 init failed!").arg(idVendor).arg(idProduct);
        zkDevice->deleteLater();
        return nullptr;
    }
}
}  // namespace Kiran
