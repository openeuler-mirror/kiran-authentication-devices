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

#include "driver-factory.h"
#include <qt5-log-i.h>
#include <QMutex>
#include "auth-enum.h"
#include "driver/driver.h"

namespace Kiran
{
DriverFactory::DriverFactory(QObject* parent) : QObject(parent)
{
}

DriverFactory* DriverFactory::getInstance()
{
    static QMutex mutex;
    static QScopedPointer<DriverFactory> pInst;
    if (Q_UNLIKELY(!pInst))
    {
        QMutexLocker locker(&mutex);
        if (pInst.isNull())
        {
            pInst.reset(new DriverFactory());
        }
    }
    return pInst.data();
}

DriverFactory::~DriverFactory()
{
}

QSharedPointer<Driver> DriverFactory::getDriver(const QString& driverName, const QString& libPath)
{
    QSharedPointer<Driver> driver = findDriverFromMap(driverName);
    if (driver.isNull())
    {
        return driver;
    }

    if (!driver->initDriver())
    {
        KLOG_ERROR() << QString("init driver %1 failed").arg(driverName);
        return QSharedPointer<Driver>();
    }
    else
    {
        KLOG_INFO() << QString("init driver %1 success").arg(driverName);
        return driver;
    }
}

void DriverFactory::registerDriver(QString driverName, std::function<Driver*()> func)
{
    m_driverFuncMap.insert(driverName, func);
}

QSharedPointer<Driver> DriverFactory::findDriverFromMap(const QString& driverName)
{
    /**
     * NOTE:不能直接调用m_driverFuncMap.value(driverName)来获取Driver派生类的构造
     * 当调用value(driverName)时，若未找到对应key，则会返回默认值，该默认值为T，即std::function<Kiran::Driver*()>
     * Driver是一个抽象类不能被实例化，并且也不能从返回的默认值中判断是否为我们需要的子类构造
     */

    QStringList driverNameList = m_driverFuncMap.keys();
    KLOG_DEBUG() << "driverNameList:" << driverNameList;

    // 如果driverName以ukey-skf-开头，则统一查询ukey-skf并生成ukey-skf-driver类
    if (driverName.contains(UKEY_SKF_DRIVER_NAME))
    {
        // 查询ukey-skf
        if (driverNameList.contains(UKEY_SKF_DRIVER_NAME))
        {
            // NOTE:所有的skf标准Ukey都使用相同的接口
            auto driverClass = m_driverFuncMap.value(UKEY_SKF_DRIVER_NAME);
            return QSharedPointer<Driver>(driverClass());
        }
    }
    else
    {
        if (driverNameList.contains(driverName))
        {
            auto driverClass = m_driverFuncMap.value(driverName);
            return QSharedPointer<Driver>(driverClass());
        }
    }

    return QSharedPointer<Driver>();
}

}  // namespace Kiran
