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

#include "device-creator.h"
#include <qt5-log-i.h>
#include <QMutex>
#include "auth-device.h"
#include "auth-enum.h"
#include "config-helper.h"

namespace Kiran
{

DeviceCereator::DeviceCereator(QObject *parent) : QObject(parent)
{
}

DeviceCereator *DeviceCereator::getInstance()
{
    static QMutex mutex;
    static QScopedPointer<DeviceCereator> pInst;
    if (Q_UNLIKELY(!pInst))
    {
        QMutexLocker locker(&mutex);
        if (pInst.isNull())
        {
            pInst.reset(new DeviceCereator());
        }
    }
    return pInst.data();
}

DeviceCereator::~DeviceCereator()
{
}

AuthDeviceList DeviceCereator::createDevices(const QString &vid, const QString &pid, DriverPtr driver)
{
    AuthDeviceList deviceList;
    QStringList driverNameList = m_deviceFuncMap.keys();

    if(!driverNameList.contains(driver->getName()))
    {
        KLOG_INFO() << QString("driver: %1 is not found in the driver list, Failed to get the device object").arg(driver->getName());
        return deviceList;
    }
    auto func = m_deviceFuncMap.value(driver->getName());

    // XXX:先特殊处理iristarDevice，人脸和虹膜识别合一的设备，该创建方式需要优化
    if (driver->getName() == IRISTAR_DRIVER_NAME)
    {
        AuthDevice *faceDevice = func(vid, pid, driver);
        faceDevice->setDeviceType(DEVICE_TYPE_Face);
        AuthDevicePtr faceDevicePtr(faceDevice);

        AuthDevice *irisDevice = func(vid, pid, driver);
        irisDevice->setDeviceType(DEVICE_TYPE_Iris);
        AuthDevicePtr irisDevicePtr(irisDevice);

        if ((faceDevicePtr->init()) &&
            (irisDevicePtr->init()))
        {
            deviceList << faceDevicePtr << irisDevicePtr;
            return deviceList;
        }
    }
    else
    {
        AuthDevice *device = func(vid, pid, driver);
        AuthDevicePtr devicePtr(device);
        if (devicePtr->init())
        {
            deviceList << devicePtr;
            return deviceList;
        }
    }
    
    KLOG_ERROR() << QString("device %1:%2 init failed!").arg(vid).arg(pid);
    return AuthDeviceList();
}

void DeviceCereator::registerDevice(QString driverName, std::function<AuthDevice *(const QString &vid, const QString &pid, DriverPtr driver)> func)
{
    m_deviceFuncMap.insert(driverName, func);
}

}  // namespace Kiran
