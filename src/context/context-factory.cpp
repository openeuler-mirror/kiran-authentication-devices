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

#include "context-factory.h"
#include <qt5-log-i.h>
#include <QMutex>
#include "kiran-auth-device-i.h"
#include "third-party-device.h"

namespace Kiran
{

ContextFactory* ContextFactory::getInstance()
{
    static QMutex mutex;
    static QScopedPointer<ContextFactory> pInst;
    if (Q_UNLIKELY(!pInst))
    {
        QMutexLocker locker(&mutex);
        if (pInst.isNull())
        {
            pInst.reset(new ContextFactory());
        }
    }
    return pInst.data();
}

void ContextFactory::registerContext(std::function<Context*()> func)
{
    m_listContextFunc.append(func);
}

void ContextFactory::createContext()
{
    Q_FOREACH (auto func, m_listContextFunc)
    {
        m_contexts << QSharedPointer<Context>(func());
    }
}

ContextFactory::ContextFactory(QObject* parent)
    : QObject{parent}
{
}

AuthDevicePtr ContextFactory::createDevice(const QString& idVendor, const QString& idProduct)
{
    if (m_contexts.count() == 0)
    {
        createContext();
    }

    // TODO:先从内置默认支持的设备开始搜索，最后才搜索第三方设备
    AuthDevicePtr device = nullptr;
    if (isDeviceSupported(idVendor, idProduct))
    {
        Q_FOREACH (auto context, m_contexts)
        {
            device = context->createDevice(idVendor, idProduct);
            if (device != nullptr)
            {
                return device;
            }
        }
    }
    return nullptr;
}

bool ContextFactory::isDeviceSupported(const QString& idVendor, const QString& idProduct)
{
    // TODO:先从内置默认支持的设备开始搜索，最后才搜索第三方设备
    const int count = sizeof(ThirdPartyDeviceSupportedTable) / sizeof(ThirdPartyDeviceSupportedTable[0]);
    for (int i = 0; i < count; i++)
    {
        const ThirdPartyDeviceSupported* thirdPartyDevice = ThirdPartyDeviceSupportedTable + i;
        if ((thirdPartyDevice->idVendor == idVendor) && (thirdPartyDevice->idProduct == idProduct))
        {
            return true;
        }
    }

    return false;
}

void ContextFactory::DestoryContext(Context* context)
{
}

}  // namespace Kiran
