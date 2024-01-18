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

#include "config-helper.h"
#include <qt5-log-i.h>
#include <QSettings>
#include "auth-enum.h"
#include "config.h"

namespace Kiran
{
DeviceConf ConfigHelper::getDeviceConf(const QString &vid, const QString &pid)
{
    QSettings confSettings(DEVICE_CONF, QSettings::NativeFormat);
    QStringList deviceConfList = confSettings.childGroups();

    Q_FOREACH (auto deviceConf, deviceConfList)
    {
        confSettings.beginGroup(deviceConf);

        QStringList idList = confSettings.value("Id").toStringList();
        for (const QString &id : idList)
        {
            if (id == QString("%1:%2").arg(vid).arg(pid))
            {
                DeviceConf conf;
                conf.deviceName = confSettings.value("Name").toString();
                conf.type = confSettings.value("Type").toInt();
                conf.vid = vid;
                conf.pid = pid;
                conf.driver = confSettings.value("Driver").toString();
                return conf;
            }
        }

        confSettings.endGroup();
    }

    return DeviceConf();
}

DriverConf ConfigHelper::getDriverConf(const QString &vid, const QString &pid)
{
    QString driverName = getDeviceConf(vid, pid).driver;

    DriverConf driverConf;
    QSettings confSettings(DRIVER_CONF, QSettings::NativeFormat);
    confSettings.beginGroup(driverName);

    driverConf.driverName = driverName;
    driverConf.enable = confSettings.value("Enable").toBool();
    driverConf.type = confSettings.value("Type").toInt();
    driverConf.libPath = confSettings.value("LibPath").toString();

    confSettings.endGroup();

    return driverConf;
}

QString ConfigHelper::getDriverName(const QString &vid, const QString &pid)
{
    DeviceConf conf = getDeviceConf(vid, pid);
    return conf.driver;
}

QString ConfigHelper::getDeviceName(const QString &vid, const QString &pid)
{
    DeviceConf conf = getDeviceConf(vid, pid);
    return conf.deviceName;
}

QString ConfigHelper::getLibPath(const QString &vid, const QString &pid)
{
    DriverConf driverConf = getDriverConf(vid, pid);
    return driverConf.libPath;
}

int ConfigHelper::getDeviceType(const QString &vid, const QString &pid)
{
    DeviceConf conf = getDeviceConf(vid, pid);
    return conf.type;
}

QStringList ConfigHelper::getDriverList()
{
    QSettings confSettings(DRIVER_CONF, QSettings::NativeFormat);
    QStringList driverList = confSettings.childGroups();
    return driverList;
}

bool ConfigHelper::driverEnabled(const QString &vid, const QString &pid)
{
    DeviceConf deviceConf = getDeviceConf(vid, pid);
    QSettings confSettings(DRIVER_CONF, QSettings::NativeFormat);
    confSettings.beginGroup(deviceConf.driver);

    QVariant varEnable = confSettings.value("Enable");
    bool enable = (varEnable.isValid() && (varEnable.toString() == "true")) ? true : false;

    confSettings.endGroup();

    return enable;
}

bool ConfigHelper::driverEnabled(const QString &driverName)
{
    bool enable = false;
    QSettings confSettings(DRIVER_CONF, QSettings::NativeFormat);
    QStringList driverList = confSettings.childGroups();
    if (driverList.contains(driverName))
    {
        enable = confSettings.value(QString("%1/Enable").arg(driverName)).toBool();
    }    
    return enable;
}

void ConfigHelper::setDriverEnabled(const QString &driverName, bool enable)
{
    QSettings confSettings(DRIVER_CONF, QSettings::NativeFormat);
    QStringList driverList = confSettings.childGroups();
    if (driverList.contains(driverName))
    {
        confSettings.setValue(QString("%1/Enable").arg(driverName), QVariant(enable));
        KLOG_INFO() << QString("driver: %1 %2").arg(driverName).arg(enable ? "enable" : "disable");
    }
}

bool ConfigHelper::isDeviceSupported(const QString &vid, const QString &pid)
{
    QSettings confSettings(DEVICE_CONF, QSettings::NativeFormat);
    QStringList deviceConfList = confSettings.childGroups();

    Q_FOREACH (auto deviceConf, deviceConfList)
    {
        confSettings.beginGroup(deviceConf);

        QStringList idList = confSettings.value("Id").toStringList();
        for (const QString &id : idList)
        {
            if (id == QString("%1:%2").arg(vid).arg(pid))
            {
                return true;
            }
        }

        confSettings.endGroup();
    }
    return false;
}

QList<DeviceInfo> ConfigHelper::getDeviceIDsSupportedByDriver(const QString &driverName)
{
    QList<DeviceInfo> deviceInfos;

    QSettings confSettings(DEVICE_CONF, QSettings::NativeFormat);
    QStringList deviceList = confSettings.childGroups();
    for (auto deviceConf : deviceList)
    {
        confSettings.beginGroup(deviceConf);
        if (confSettings.value("Driver").toString() != driverName)
        {
            confSettings.endGroup();
            continue;
        }

        QStringList idList = confSettings.value("Id").toStringList();
        for (const QString &id : idList)
        {
            QStringList idItems = id.split(":");
            if (idItems.count() != 2)
            {
                continue;
            }

            DeviceInfo deviceinfo;
            deviceinfo.idVendor = idItems.value(0);
            deviceinfo.idProduct = idItems.value(1);

            deviceInfos << deviceinfo;
          }
        confSettings.endGroup();
    }

    return deviceInfos;
}

}  // namespace Kiran