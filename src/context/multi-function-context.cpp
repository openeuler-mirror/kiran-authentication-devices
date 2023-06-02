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

#include "multi-function-context.h"
#include <qt5-log-i.h>
#include "context/context-factory.h"
#include "device/multi-function/mf-iristar-device.h"
#include "third-party-device.h"
#include "utils.h"

namespace Kiran
{
REGISTER_CONTEXT(MultiFunctionContext);

MultiFunctionContext::MultiFunctionContext(QObject* parent)
    : Context{parent}
{
}

AuthDeviceList MultiFunctionContext::createDevices(const QString& idVendor, const QString& idProduct)
{
    AuthDeviceList list;
    if ((idVendor != IRISTAR_ID_VENDOR) || (idProduct != IRISTAR_ID_PRODUCT))
    {
        return list;
    }

    // TODO：从配置文件中拿到该设备所支持的两种类型
    QList<DeviceType> deviceTypes = {DEVICE_TYPE_Iris, DEVICE_TYPE_Face};
    Q_FOREACH (auto type, deviceTypes)
    {
        auto device = createIriStarDevice(idVendor, idProduct, type);
        if (!device.isNull())
        {
            list << device;
        }
    }

    return list;
}

// TODO:没必要这么多参数，暂时这样
AuthDevicePtr MultiFunctionContext::createIriStarDevice(const QString& idVendor, const QString& idProduct, DeviceType deviceType)
{
    AuthDevicePtr invalidDevice;

    auto iriStarDevice = QSharedPointer<MFIriStarDevice>(new MFIriStarDevice(deviceType));

    if (!Utils::driverEnabled(iriStarDevice->deviceDriver()))
    {
        KLOG_INFO() << QString("driver %1 is disabled! device %2:%3 can't be used")
                           .arg(iriStarDevice->deviceDriver())
                           .arg(idVendor)
                           .arg(idProduct);
        return invalidDevice;
    }

    if (!iriStarDevice->init())
    {
        KLOG_ERROR() << QString("device %1:%2 init failed!").arg(idVendor).arg(idProduct);
        iriStarDevice->deleteLater();
        return invalidDevice;
    }

    QString deviceName = Utils::getDeviceName(idVendor, idProduct);
    if (deviceName.isEmpty())
    {
        deviceName = "IrisStar";
    }
    iriStarDevice->setDeviceName(deviceName);
    iriStarDevice->setDeviceInfo(idVendor, idProduct);

    return iriStarDevice;
}

}  // namespace Kiran
