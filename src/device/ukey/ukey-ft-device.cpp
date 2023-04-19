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

#include "ukey-ft-device.h"
#include <dlfcn.h>
#include <qt5-log-i.h>
#include <QCryptographicHash>
#include "auth-enum.h"
#include "auth_device_adaptor.h"
#include "feature-db.h"

namespace Kiran
{
#define FT_UKEY_DRIVER_LIB "libes_3000gm.so"
#define UKEY_APP_NAME "KIRAN-AUTHENTICATION-DEVICES"
#define UKEY_CONTAINER_NAME "1003-3001"

UKeyFTDevice::UKeyFTDevice(QObject *parent) : AuthDevice{parent},
                                              m_libHandle(nullptr),
                                              m_appHandle(nullptr),
                                              m_devHandle(nullptr),
                                              m_containerHandle(nullptr)
{
    setDeviceType(DEVICE_TYPE_UKey);
    setDeviceDriver(FT_UKEY_DRIVER_LIB);
}

UKeyFTDevice::~UKeyFTDevice()
{
    m_driver->closeContainer(m_containerHandle);
    m_driver->closeApplication(m_appHandle);
    m_driver->disConnectDev(m_devHandle);
    m_containerHandle = nullptr;
    m_appHandle = nullptr;
    m_devHandle = nullptr;
}

bool UKeyFTDevice::initDevice()
{
    m_driver = QSharedPointer<UKeySKFDriver>(new UKeySKFDriver());
    if (!m_driver->loadLibrary(FT_UKEY_DRIVER_LIB))
    {
        return false;
    }
    m_devHandle = m_driver->connectDev();
    if (!m_devHandle)
    {
        KLOG_DEBUG() << "";
        return false;
    }

    return true;
}

BDriver *UKeyFTDevice::getDriver()
{
    return nullptr;
}

void UKeyFTDevice::doingUKeyEnrollStart(const QString &pin, bool rebinding)
{
    if (rebinding)
    {
        ULONG ulReval = m_driver->devAuth(m_devHandle);
        if (ulReval == SAR_OK)
        {
            m_driver->deleteAllApplication(m_devHandle);
            DeviceInfo deviceInfo = this->deviceInfo();
            QStringList idList = FeatureDB::getInstance()->getFeatureIDs(deviceInfo.idVendor, deviceInfo.idProduct);
            Q_FOREACH (auto id, idList)
            {
                FeatureDB::getInstance()->deleteFeature(id);
            }
            bindingCurrentUser();
        }
        else
        {
            KLOG_ERROR() << "rebinding failed";
        }
    }
    else
    {
        bindingCurrentUser();
    }
    internalStopEnroll();
}

void UKeyFTDevice::bindingCurrentUser()
{
    if (isExistPublicKey())
    {
        notifyUKeyEnrollProcess(ENROLL_PROCESS_REPEATED_ENROLL);
        return;
    }

    ECCPUBLICKEYBLOB publicKey = genKeyPair();
    if (publicKey.BitLen != 0)
    {
        /**
         * 存入PublicKey,生成FID，并返回FID，FID标识PublicKey
         * 不用保存PublicKey和systemUser的关系,目前只有一个用户
         */
        QByteArray keyFeature;
        QByteArray xCoordinateArray((char *)publicKey.XCoordinate, 64);
        QByteArray yCoordinateArray((char *)publicKey.YCoordinate, 64);
        keyFeature.append(publicKey.BitLen);
        keyFeature.append(xCoordinateArray);
        keyFeature.append(yCoordinateArray);
        KLOG_DEBUG() << "keyFeature:" << keyFeature;

        QString featureID = QCryptographicHash::hash(keyFeature, QCryptographicHash::Md5).toHex();
        DeviceInfo deviceInfo = this->deviceInfo();

        if (FeatureDB::getInstance()->addFeature(featureID, keyFeature, deviceInfo))
        {
            notifyUKeyEnrollProcess(ENROLL_PROCESS_SUCCESS, SAR_OK, featureID);
        }
        else
        {
            KLOG_DEBUG() << "save feature fail";
            notifyUKeyEnrollProcess(ENROLL_PROCESS_SAVE_FAIL);
        }
    }
    else
    {
        notifyUKeyEnrollProcess(ENROLL_PROCESS_SAVE_FAIL);
    }
}

bool UKeyFTDevice::isExistPublicKey()
{
    DeviceInfo deviceInfo = this->deviceInfo();
    auto features = FeatureDB::getInstance()->getFeatures(deviceInfo.idVendor, deviceInfo.idProduct);
    if (features.count() != 0)
    {
        return true;
    }
    else
    {
        return false;
    }
}

ECCPUBLICKEYBLOB UKeyFTDevice::genKeyPair()
{
    ECCPUBLICKEYBLOB publicKey = {0};
    if (!isExistsApplication(UKEY_APP_NAME))
    {
        // NOTE:必须通过设备认证后才能在设备内创建和删除应用
        ULONG ulReval = m_driver->devAuth(m_devHandle);
        if (ulReval != SAR_OK)
        {
            KLOG_ERROR() << "Device auth failure: " << m_driver->getErrorReason(ulReval);
            return publicKey;
        }
        else
        {
            KLOG_DEBUG() << "device auth success";
        }
        m_driver->deleteAllApplication(m_devHandle);
        KLOG_DEBUG() << "m_devHandle:" << m_devHandle;
        KLOG_DEBUG() << "m_pin:" << m_pin;
        m_appHandle = m_driver->createApplication(m_devHandle, m_pin, UKEY_APP_NAME);
        m_containerHandle = m_driver->createContainer(m_appHandle, m_pin, UKEY_CONTAINER_NAME, &m_retryCount);
        if (!m_appHandle || !m_containerHandle)
        {
            return publicKey;
        }
    }

    m_appHandle = m_driver->onOpenApplication(m_devHandle, (LPSTR)UKEY_APP_NAME);
    m_containerHandle = m_driver->onOpenContainer(m_appHandle, m_pin, UKEY_CONTAINER_NAME, &m_retryCount);
    if (!m_appHandle || !m_containerHandle)
    {
        return publicKey;
    }

    ULONG ret = m_driver->genECCKeyPair(m_containerHandle, &publicKey);
    if (ret == SAR_OK)
    {
        KLOG_DEBUG() << "gen ecc key pair success";
    }
    else
    {
        KLOG_ERROR() << "gen ecc key pair failed:" << m_driver->getErrorReason(ret);
    }

    return publicKey;
}

bool UKeyFTDevice::isExistsApplication(const QString &appName)
{
    QString appNames = m_driver->enumApplication(m_devHandle);
    KLOG_DEBUG() << "enum app names:" << appNames;
    if (appNames.contains(appName))
    {
        return true;
    }
    return false;
}

void UKeyFTDevice::doingUKeyIdentifyStart(const QString &pin)
{
    QList<QByteArray> saveList;
    DeviceInfo deviceInfo = this->deviceInfo();
    if (m_identifyIDs.isEmpty())
    {
        saveList = FeatureDB::getInstance()->getFeatures(deviceInfo.idVendor, deviceInfo.idProduct);
    }
    else
    {
        Q_FOREACH (auto id, m_identifyIDs)
        {
            QByteArray feature = FeatureDB::getInstance()->getFeature(id);
            if (!feature.isEmpty())
                saveList << feature;
        }
    }

    if (saveList.count() != 0)
    {
        for (int j = 0; j < saveList.count(); j++)
        {
            auto saveTemplate = saveList.value(j);
            identifyKeyFeature(saveTemplate);
        }
    }
    else
    {
        KLOG_DEBUG() << "no found feature id";
    }

    internalStopIdentify();
}

void UKeyFTDevice::internalStopEnroll()
{
    if (deviceStatus() == DEVICE_STATUS_DOING_ENROLL)
    {
        m_driver->closeContainer(m_containerHandle);
        m_driver->closeApplication(m_appHandle);
        acquireFeatureStop();
        m_enrollTemplates.clear();
        setDeviceStatus(DEVICE_STATUS_IDLE);
        clearWatchedServices();
        KLOG_DEBUG() << "stop Enroll";
    }
}

void UKeyFTDevice::internalStopIdentify()
{
    if (deviceStatus() == DEVICE_STATUS_DOING_IDENTIFY)
    {
        m_driver->closeContainer(m_containerHandle);
        m_driver->closeApplication(m_appHandle);
        acquireFeatureStop();
        m_identifyIDs.clear();
        setDeviceStatus(DEVICE_STATUS_IDLE);
        clearWatchedServices();
        KLOG_DEBUG() << "stopIdentify";
    }
}

void UKeyFTDevice::identifyKeyFeature(QByteArray keyFeature)
{
    m_appHandle = m_driver->onOpenApplication(m_devHandle, (LPSTR)UKEY_APP_NAME);
    if (m_appHandle == nullptr)
    {
        notifyUKeyIdentifyProcess(IDENTIFY_PROCESS_NO_MATCH);
        return;
    }

    m_containerHandle = m_driver->onOpenContainer(m_appHandle, m_pin, UKEY_CONTAINER_NAME, &m_retryCount);
    if (m_containerHandle == nullptr)
    {
        notifyUKeyIdentifyProcess(IDENTIFY_PROCESS_NO_MATCH);
        return;
    }

    ECCSIGNATUREBLOB Signature = {0};
    ULONG ret = m_driver->authSignData(m_containerHandle, m_devHandle, Signature);
    if (ret != SAR_OK)
    {
        KLOG_DEBUG() << "auth sign data failed:" << m_driver->getErrorReason(ret);
        notifyUKeyIdentifyProcess(IDENTIFY_PROCESS_NO_MATCH, ret);
        return;
    }

    ECCPUBLICKEYBLOB eccPubKey;
    eccPubKey.BitLen = keyFeature.left(1).at(0);
    auto xCoordinateArray = keyFeature.mid(1, sizeof(eccPubKey.XCoordinate));
    auto yCoordinateArray = keyFeature.mid(sizeof(eccPubKey.XCoordinate) + 1);

    memcpy(eccPubKey.XCoordinate, (unsigned char *)xCoordinateArray.data(), ECC_MAX_XCOORDINATE_BITS_LEN / 8);
    memcpy(eccPubKey.YCoordinate, (unsigned char *)yCoordinateArray.data(), ECC_MAX_YCOORDINATE_BITS_LEN / 8);

    ret = m_driver->verifyData(m_devHandle, Signature, eccPubKey);
    if (ret != SAR_OK)
    {
        KLOG_DEBUG() << "verify data failed:" << m_driver->getErrorReason(ret);
        notifyUKeyIdentifyProcess(IDENTIFY_PROCESS_NO_MATCH, ret);
    }
    else
    {
        notifyUKeyIdentifyProcess(IDENTIFY_PROCESS_MACTCH);
    }
}

QByteArray UKeyFTDevice::acquireFeature()
{
    return QByteArray();
}

void UKeyFTDevice::acquireFeatureStop()
{
}
void UKeyFTDevice::acquireFeatureFail()
{
}

void UKeyFTDevice::notifyUKeyEnrollProcess(EnrollProcess process, ULONG error, const QString &featureID)
{
    QString message;
    switch (process)
    {
    case ENROLL_PROCESS_SUCCESS:
        message = tr("Successed binding user");
        Q_EMIT m_dbusAdaptor->EnrollStatus(featureID, 100, ENROLL_RESULT_COMPLETE, message);
        break;
    case ENROLL_PROCESS_SAVE_FAIL:
        message = tr("Binding user failed");
        Q_EMIT m_dbusAdaptor->EnrollStatus("", 0, ENROLL_RESULT_FAIL, message);
        break;
    case ENROLL_PROCESS_REPEATED_ENROLL:
        message = tr("UKey has been bound");
        Q_EMIT m_dbusAdaptor->EnrollStatus("", 0, ENROLL_RESULT_UKEY_EXIST_BINDING, message);
    default:
        break;
    }
    if (!message.isEmpty())
    {
        if (!featureID.isEmpty())
        {
            KLOG_DEBUG() << QString("%1, feature id:%2").arg(message).arg(featureID);
        }
        else
        {
            KLOG_DEBUG() << message;
        }
    }
}

void UKeyFTDevice::notifyUKeyIdentifyProcess(IdentifyProcess process, ULONG error, const QString &featureID)
{
    QString message, reason;
    if (error != SAR_OK)
    {
        reason = m_driver->getErrorReason(error);
        KLOG_DEBUG() << "fail reason:" << reason;
    }

    KLOG_DEBUG() << "m_retryCount:" << m_retryCount;
    switch (process)
    {
    case IDENTIFY_PROCESS_NO_MATCH:
        message = tr("identify fail!");
        // 目前只需要返回有关pin码的错误信息
        if (reason.contains("pin"))
        {
            message.append(reason);
        }
        message.append(QString(",remaining retry count: %1").arg(m_retryCount));
        Q_EMIT m_dbusAdaptor->IdentifyStatus("", IDENTIFY_RESULT_NOT_MATCH, message);
        break;
    case IDENTIFY_PROCESS_MACTCH:
        message = tr("identify ukey success");
        Q_EMIT m_dbusAdaptor->IdentifyStatus(featureID, IDENTIFY_RESULT_MATCH, message);
        break;
    default:
        break;
    }

    if (!message.isEmpty())
    {
        KLOG_DEBUG() << QString("%1, feature id:%2").arg(message).arg(featureID);
    }
}

}  // namespace Kiran