#include "ukey-manager.h"
#include <qt5-log-i.h>
#include <iostream>
#include "ukey-skf-driver.h"
#include  <QSettings>
#include "auth-enum.h"
#include "config.h"

#define DEFAULT_USER_PINCODE "12345678"

namespace Kiran
{

UkeyManager::UkeyManager() : m_devHandle(nullptr),
                             m_appHandle(nullptr),
                             m_containerHandle(nullptr)
{
    m_driver = new UKeySKFDriver();
}

UkeyManager::~UkeyManager()
{
    if (m_driver->isLoaded())
    {
        if (m_containerHandle)
        {
            m_driver->closeContainer(m_containerHandle);
        }

        if (m_appHandle)
        {
            m_driver->closeApplication(m_appHandle);
        }

        if (m_devHandle)
        {
            m_driver->disConnectDev(m_devHandle);
        }
    }
    delete m_driver;
}

bool UkeyManager::initDriver()
{
    QSettings confSettings(UKEY_MANAGER_CONF, QSettings::NativeFormat);
    QString libPath = confSettings.value("ukey/LibPath").toString();  
    if (!m_driver->loadLibrary(libPath))
    {
        KLOG_DEBUG() << "load library  failed";
        std::cout << "load library  failed" << std::endl;
        return false;
    }
    m_devHandle = m_driver->connectDev();
    if (!m_devHandle)
    {
        KLOG_DEBUG() << "connect device failed";
        std::cout << "connect device failed" << std::endl;
        return false;
    }
    return true;
}

ULONG UkeyManager::resetUkey()
{
    ULONG ulReval = m_driver->resetUkey(m_devHandle);
    return ulReval;
}

ULONG UkeyManager::changePin(const QString &userType, const QString &currentPin, const QString &newPin, ULONG *retryCount)
{
    int type;
    if (userType == "admin")
    {
        type = ADMIN_TYPE;
    }
    else if (userType == "user")
    {
        type = USER_TYPE;
    }
    else
    {
        KLOG_DEBUG() << "invalid user type";
        std::cout << "invalid user type" << std::endl;
        return SAR_FAIL;
    }
    KLOG_DEBUG() << "type:" << type;
    ULONG ret = m_driver->changePin(m_devHandle, type, currentPin, newPin, retryCount);
    return ret;
}

ULONG UkeyManager::unblockPin(const QString &adminPin, const QString &userPin, ULONG *retryCount)
{
    ULONG ret = m_driver->unblockPin(m_devHandle, adminPin, userPin, retryCount);
    return ret;
}

QString UkeyManager::getErrorReason(ULONG error)
{
    return m_driver->getErrorReason(error);
}
}  // namespace Kiran
