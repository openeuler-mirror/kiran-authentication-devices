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

#include "fp-zk-context.h"
#include <qt5-log-i.h>
#include <QSettings>
#include "device/fingerprint/fp-zk-device.h"
#include "third-party-device.h"
#include "utils.h"
#include "context/context-factory.h"

namespace Kiran
{
REGISTER_CONTEXT(FPZKContext);

FPZKContext::FPZKContext(QObject* parent)
    : Context{parent}
{
}

// fp-zk-context 需要管理多个so，可以生成不同 so的设备
AuthDevicePtr FPZKContext::createDevice(const QString& idVendor, const QString& idProduct)
{
    if (idVendor != ZK_ID_VENDOR)
    {
        return nullptr;
    }
    /**
     * NOTE:创建对象后，读取配置文件，判断驱动是否开启，再判断是否初始化该设备
     */
    auto zkDevice = QSharedPointer<FPZKDevice>(new FPZKDevice());
    if (!Utils::driverEnabled(zkDevice->deviceDriver()))
    {
        KLOG_INFO() << QString("driver %1 is disabled! device %2:%3 can't be used")
                           .arg(zkDevice->deviceDriver())
                           .arg(idVendor)
                           .arg(idProduct);
        return nullptr;
    }

    if (!zkDevice->init())
    {
        KLOG_ERROR() << QString("device %1:%2 init failed!").arg(idVendor).arg(idProduct);
        zkDevice->deleteLater();
        return nullptr;
    }

    QString deviceName = Utils::getDeviceName(idVendor, idProduct);
    if (deviceName.isEmpty())
    {
        deviceName = "ZK Teco";
    }
    zkDevice->setDeviceName(deviceName);
    zkDevice->setDeviceInfo(idVendor, idProduct);
    return zkDevice;
}
}  // namespace Kiran
