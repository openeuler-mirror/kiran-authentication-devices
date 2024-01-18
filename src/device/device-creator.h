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
#include <QMap>
#include <QObject>
#include <QSharedPointer>
#include <functional>
#include "driver/driver.h"

namespace Kiran
{
class ConfigHelper;
class AuthDevice;
typedef QSharedPointer<AuthDevice> AuthDevicePtr;
typedef QList<AuthDevicePtr> AuthDeviceList;
typedef QSharedPointer<Driver> DriverPtr;

class DeviceCereator : public QObject
{
    Q_OBJECT
private:
    DeviceCereator(QObject *parent = nullptr);

public:
    static DeviceCereator *getInstance();
    ~DeviceCereator();

    AuthDeviceList createDevices(const QString &vid, const QString &pid, DriverPtr driver);

    void registerDevice(QString driverName,
                        std::function<AuthDevice *(const QString &vid, const QString &pid, DriverPtr driver)> func);

private:
    QMap<QString, std::function<AuthDevice *(const QString &vid, const QString &pid, DriverPtr driver)>> m_deviceFuncMap;
};

class DeviceRegisterHelper
{
public:
    DeviceRegisterHelper(QString driverName,
                         std::function<AuthDevice *(const QString &vid, const QString &pid, DriverPtr driver)> func)
    {
        DeviceCereator::getInstance()->registerDevice(driverName, func);
    }
};

/**
 * 定义全局静态变量，利用全局静态变量在进程开始时创建（在main函数之前初始化）
 * 将所有Device子类构造函数注册到DeviceCreator单例对象中
 */
#define REGISTER_DEVICE(driverName, className)                              \
    static DeviceRegisterHelper className##ObjectRegisterHelper(driverName, \
                                                                [](const QString &vid, const QString &pid, DriverPtr driver) -> className * { return new className(vid, pid, driver); })

}  // namespace Kiran
