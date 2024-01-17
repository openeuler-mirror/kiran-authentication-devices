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
#include <QString>
#include "auth-enum.h"

namespace Kiran
{
struct DeviceConf
{
    QString deviceName;
    QString name;
    int type;
    QString vid;
    QString pid;
    QString driver;
};

struct DriverConf
{
    QString driverName;
    bool enable; 
    int type;
    QString libPath;
};

class ConfigHelper
{
public:
    ConfigHelper() {};
    ~ConfigHelper(){};

    static DeviceConf getDeviceConf(const QString &vid, const QString &pid);
    static DriverConf getDriverConf(const QString &vid, const QString &pid);
    
    static QString getDriverName(const QString &vid, const QString &pid);
    static QString getDeviceName(const QString &vid, const QString &pid);
    static QString getLibPath(const QString &vid, const QString &pid);
    static int getDeviceType(const QString &vid, const QString &pid);
    static QStringList getDriverList();

    static bool driverEnabled(const QString &vid, const QString &pid);
    static bool driverEnabled(const QString & driverName);

    static void setDriverEnabled(const QString& driverName, bool enable);
    static bool isDeviceSupported(const QString &vid, const QString &pid);

    static QList<DeviceInfo> getDeviceIDsSupportedByDriver(const QString& driverName);
private:
};

}  // namespace Kiran