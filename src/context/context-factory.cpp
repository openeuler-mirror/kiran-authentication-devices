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

#include "context-factory.h"
#include <qt5-log-i.h>
#include <QMutex>
#include "finger-vein/fv-sd-context.h"
#include "fingerprint/fp-builtin-context.h"
#include "fingerprint/fp-zk-context.h"
#include "kiran-auth-device-i.h"
#include "third-party-device.h"
#include "ukey/ukey-ft-context.h"

namespace Kiran
{

ContextFactory* ContextFactory::instance()
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

ContextFactory::ContextFactory(QObject* parent)
    : QObject{parent}
{
    init();
}

void ContextFactory::init()
{
    m_fpZKContext = QSharedPointer<FPZKContext>(new FPZKContext());
    m_fpBuiltInContext = QSharedPointer<FPBuiltInContext>(new FPBuiltInContext());
    m_fvSDContext = QSharedPointer<FVSDContext>(new FVSDContext());
    m_ukeyFTContext = QSharedPointer<UKeyFTContext>(new UKeyFTContext());
}

AuthDevicePtr ContextFactory::createDevice(const QString& idVendor, const QString& idProduct)
{
    // TODO:先从内置默认支持的设备开始搜索，最后才搜索第三方设备
    AuthDevicePtr device = nullptr;
    const int count = sizeof(ThirdPartyDeviceSupportedTable) / sizeof(ThirdPartyDeviceSupportedTable[0]);
    for (int i = 0; i < count; i++)
    {
        const ThirdPartyDeviceSupported* thirdPartyDevice = ThirdPartyDeviceSupportedTable + i;
        if ((thirdPartyDevice->idVendor == idVendor) && (thirdPartyDevice->idProduct == idProduct))
        {
            switch (thirdPartyDevice->deviceType)
            {
            case DEVICE_TYPE_FingerPrint:
                device = createFingerPrintDevice(idVendor, idProduct);
                break;
            case DEVICE_TYPE_Face:
                break;
            case DEVICE_TYPE_FingerVein:
                device = createFingerVeinDevice(idVendor, idProduct);
                break;
            case DEVICE_TYPE_UKey:
                device = createUKeyDevice(idVendor, idProduct);
                break;
            default:
                break;
            }
            break;
        }
    }
    return device;
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

// TODO:create行为类似，考虑优化
AuthDevicePtr ContextFactory::createFingerPrintDevice(const QString& idVendor, const QString& idProduct)
{
    if (idVendor == ZK_ID_VENDOR)
    {
        return m_fpZKContext->createDevice(idVendor, idProduct);
    }
    else
    {
        return nullptr;
    };
}

AuthDevicePtr ContextFactory::createFingerVeinDevice(const QString& idVendor, const QString& idProduct)
{
    if (idVendor == SD_ID_VENDOR)
    {
        return m_fvSDContext->createDevice(idVendor, idProduct);
    }
    else
        return nullptr;
}

AuthDevicePtr ContextFactory::createUKeyDevice(const QString& idVendor, const QString& idProduct)
{
    if (idVendor == FT_ID_VENDOR)
    {
        return m_ukeyFTContext->createDevice(idVendor, idProduct);
    }
    else
    {
        return nullptr;
    };
}

Context* ContextFactory::CreateContext()
{
    return nullptr;
}

void ContextFactory::DestoryContext(Context* context)
{
}

QList<AuthDevicePtr> ContextFactory::getDevices()
{
    QList<AuthDevicePtr> devices;
    devices << m_fpZKContext->getDevices()
            << m_fpBuiltInContext->getDevices();
    return devices;
}

}  // namespace Kiran
