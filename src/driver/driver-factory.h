/**
 * Copyright (c) 2020 ~ 2023 KylinSec Co., Ltd.
 * kiran-authentication-devices is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 * http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 *
 * Author: luoqing <luoqing@kylinsec.com.cn>
 */
#pragma once
#include <QMap>
#include <QObject>
#include <QSharedPointer>
#include <functional>

namespace Kiran
{
class Driver;
class DriverFactory : public QObject
{
private:
    explicit DriverFactory(QObject *parent = nullptr);

public:
    static DriverFactory *getInstance();
    ~DriverFactory();
    QSharedPointer<Driver> getDriver(const QString &driverName, const QString &libPath = QString());

    void registerDriver(QString driverName, std::function<Driver *()>);

private:
    QSharedPointer<Driver> findDriverFromMap(const QString &driverName);

private:
    QMap<QString, std::function<Driver *()>> m_driverFuncMap;
};

class DriverRegisterHelper
{
public:
    DriverRegisterHelper(QString driverName, std::function<Driver *()> func)
    {
        DriverFactory::getInstance()->registerDriver(driverName, func);
    }
};

/**
 * 定义全局静态变量，利用全局静态变量在进程开始时创建（在main函数之前初始化）
 * 将所有driver子类构造函数注册到DriverManager单例对象中
 */
#define REGISTER_DRIVER(driverName, className) \
    static DriverRegisterHelper className##ObjectRegisterHelper(driverName, []() -> className * { return new className(); })

}  // namespace Kiran
