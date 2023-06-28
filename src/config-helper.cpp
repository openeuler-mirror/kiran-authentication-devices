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

namespace Kiran
{
DeviceConf ConfigHelper::getDeviceConf(const QString &vid, const QString &pid)
{
    QSettings confSettings(DEVICE_CONF, QSettings::NativeFormat);
    QStringList deviceConfList = confSettings.childGroups();

    Q_FOREACH (auto deviceConf, deviceConfList)
    {
        confSettings.beginGroup(deviceConf);
        if ((confSettings.value("Vid").toString() == vid) &&
            (confSettings.value("Pid").toString() == pid))
        {
            DeviceConf conf;
            conf.deviceName = confSettings.value("Name").toString();
            conf.type = confSettings.value("Type").toInt();
            conf.vid = confSettings.value("Vid").toString();
            conf.pid = confSettings.value("Pid").toString();
            conf.driver = confSettings.value("Driver").toString();
            conf.libPath = confSettings.value("LibPath").toString();

            return conf;
        }
        confSettings.endGroup();
    }

    return DeviceConf();
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
    DeviceConf conf = getDeviceConf(vid, pid);
    return conf.libPath;
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

void ConfigHelper::setDriverEnabled(const QString& driverName, bool enable)
{
    QSettings confSettings(DRIVER_CONF, QSettings::NativeFormat);
    QStringList driverList = confSettings.childGroups();
    QString enableStr;
    if (driverList.contains(driverName))
    {
        enableStr = enable ? QString("true") : QString("false");
        confSettings.setValue(QString("%1/Enable").arg(driverName), QVariant(enableStr));
        KLOG_INFO()  <<  QString("driver: %1 %2").arg(driverName).arg((enable == true) ? "enable":"disable");
    }
}

bool ConfigHelper::isDeviceSupported(const QString &vid, const QString &pid)
{
    QSettings confSettings(DEVICE_CONF, QSettings::NativeFormat);
    QStringList deviceConfList = confSettings.childGroups();

    Q_FOREACH (auto deviceConf, deviceConfList)
    {
        confSettings.beginGroup(deviceConf);
        if ((confSettings.value("Vid").toString() == vid) &&
            (confSettings.value("Pid").toString() == pid))
        {
            return true;
        }
        confSettings.endGroup();
    }
    return false;
}

}  // namespace Kiran