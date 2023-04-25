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

#include "utils.h"
#include <libudev.h>
#include <qt5-log-i.h>
#include <QJsonDocument>
#include <QJsonObject>
#include <QSettings>
#include "auth-enum.h"

namespace Kiran
{
#define CONF_FILE_DISABLE_DRIVER_NAME "Disable/DriverName"

namespace Utils
{

QString getDeviceName(const QString& idVendor, const QString& idProduct)
{
    struct udev* udev;
    udev = udev_new();

    struct udev_enumerate* enumerate = udev_enumerate_new(udev);  // 创建一个枚举器用于扫描已连接的设备
    udev_enumerate_add_match_subsystem(enumerate, "usb");
    udev_enumerate_scan_devices(enumerate);
    struct udev_list_entry* devices = udev_enumerate_get_list_entry(enumerate);  // 返回一个存储了设备所有属性信息的链表
    struct udev_list_entry* entry;

    QString deviceName;
    udev_list_entry_foreach(entry, devices)
    {
        const char* path = udev_list_entry_get_name(entry);
        struct udev_device* dev = udev_device_new_from_syspath(udev, path);  // 创建一个udev设备的映射

        QString vendor = udev_device_get_sysattr_value(dev, "idVendor");
        QString product = udev_device_get_sysattr_value(dev, "idProduct");

        if ((vendor == idVendor) && (product == idProduct))
        {
            deviceName = udev_device_get_sysattr_value(dev, "manufacturer");
            break;
        }
    }

    udev_enumerate_unref(enumerate);
    udev_unref(udev);

    return deviceName;
}

QJsonValue getValueFromJsonString(const QString& json, const QString& key)
{
    QJsonDocument jsonDoc = QJsonDocument::fromJson(json.toLocal8Bit().data());
    if (jsonDoc.isEmpty())
    {
        return QJsonValue();
    }
    QJsonObject jsonObject = jsonDoc.object();
    return jsonObject.value(key);
}

QStringList getDriverBlackList()
{
    QSettings confSettings(DRIVER_BLACK_LIST_CONF, QSettings::NativeFormat);
    return confSettings.value(CONF_FILE_DISABLE_DRIVER_NAME).toStringList();
}

bool driverEnabled(const QString& driverName)
{
    QSettings confSettings(DRIVERS_CONF, QSettings::NativeFormat);
    QVariant value = confSettings.value(QString("%1/Enable").arg(driverName));
    if (value.isValid())
    {
        if (value.toString() == "false")
        {
            return false;
        }
        else if (value.toString() == "true")
        {
            return true;
        }
        else
            return false;
    }
    else
        return false;
}

}  // namespace Utils
}  // namespace Kiran