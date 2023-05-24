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

#include "ukey-ft-device.h"
#include <dlfcn.h>
#include <qt5-log-i.h>
#include <QCryptographicHash>
#include "auth-enum.h"
#include "auth_device_adaptor.h"
#include "feature-db.h"
#include "utils.h"

namespace Kiran
{
UKeyFTDevice::UKeyFTDevice(QObject *parent) : AuthDevice{parent},
                                              m_appHandle(nullptr),
                                              m_devHandle(nullptr),
                                              m_containerHandle(nullptr)
{
    setDeviceType(DEVICE_TYPE_UKey);
    setDeviceDriver(FT_UKEY_DRIVER_LIB);
    m_driver = QSharedPointer<UKeySKFDriver>(new UKeySKFDriver());
}

UKeyFTDevice::~UKeyFTDevice()
{
}

bool UKeyFTDevice::initDriver()
{
    if (!m_driver->loadLibrary(FT_UKEY_DRIVER_LIB))
    {
        return false;
    }

    return true;
}

void UKeyFTDevice::doingEnrollStart(const QString &extraInfo)
{
    KLOG_DEBUG() << "ukey enroll start";
    QJsonValue ukeyValue = Utils::getValueFromJsonString(extraInfo, AUTH_DEVICE_JSON_KEY_UKEY);
    auto jsonObject = ukeyValue.toObject();
    m_pin = jsonObject.value(AUTH_DEVICE_JSON_KEY_PIN).toString();
    bool rebinding = jsonObject.value(AUTH_DEVICE_JSON_KEY_REBINDING).toBool();
    if (m_pin.isEmpty())
    {
        QString message = tr("The pin code cannot be empty!");
        Q_EMIT m_dbusAdaptor->EnrollStatus("", 0, ENROLL_STATUS_FAIL, message);
        KLOG_ERROR() << "The pin code cannot be empty!";
        internalStopEnroll();
        return;
    }

    m_devHandle = m_driver->connectDev();
    if (!m_devHandle)
    {
        KLOG_ERROR() << "Connect Dev failed";
        notifyUKeyEnrollProcess(ENROLL_PROCESS_FAIL);
        internalStopEnroll();
        return;
    }

    if (rebinding)
    {
        ULONG ulReval = m_driver->devAuth(m_devHandle);
        if (ulReval == SAR_OK)
        {
            m_driver->deleteAllApplication(m_devHandle);
            DeviceInfo deviceInfo = this->deviceInfo();
            QStringList idList = FeatureDB::getInstance()->getFeatureIDs(deviceInfo.idVendor, deviceInfo.idProduct, deviceType());
            Q_FOREACH (auto id, idList)
            {
                FeatureDB::getInstance()->deleteFeature(id);
            }
            bindingUKey();
        }
        else
        {
            KLOG_ERROR() << "rebinding failed";
        }
    }
    else
    {
        bindingUKey();
    }
    internalStopEnroll();
}

void UKeyFTDevice::bindingUKey()
{
    if (isExistPublicKey())
    {
        notifyUKeyEnrollProcess(ENROLL_PROCESS_REPEATED_ENROLL);
        return;
    }
    ECCPUBLICKEYBLOB publicKey = {0};
    ULONG ret = genKeyPair(&publicKey);

    if (ret != SAR_OK)
    {
        KLOG_ERROR() << "gen ecc key pair failed:" << m_driver->getErrorReason(ret);
        notifyUKeyEnrollProcess(ENROLL_PROCESS_FAIL, ret);
        return;
    }
    KLOG_DEBUG() << "gen ecc key pair success";

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

    if (FeatureDB::getInstance()->addFeature(featureID, keyFeature, deviceInfo, deviceType()))
    {
        notifyUKeyEnrollProcess(ENROLL_PROCESS_SUCCESS, SAR_OK, featureID);
    }
    else
    {
        KLOG_DEBUG() << "save feature fail";
        notifyUKeyEnrollProcess(ENROLL_PROCESS_FAIL);
    }
}

bool UKeyFTDevice::isExistPublicKey()
{
    DeviceInfo deviceInfo = this->deviceInfo();
    auto features = FeatureDB::getInstance()->getFeatures(deviceInfo.idVendor, deviceInfo.idProduct, deviceType());
    if (features.count() != 0)
    {
        return true;
    }
    else
    {
        return false;
    }
}

ULONG UKeyFTDevice::genKeyPair(ECCPUBLICKEYBLOB *publicKey)
{
    ULONG ulReval;
    if (!isExistsApplication(UKEY_APP_NAME))
    {
        // NOTE:必须通过设备认证后才能在设备内创建和删除应用
        ulReval = m_driver->devAuth(m_devHandle);
        if (ulReval != SAR_OK)
        {
            KLOG_ERROR() << "Device auth failure: " << m_driver->getErrorReason(ulReval);
            return ulReval;
        }
        else
        {
            KLOG_DEBUG() << "device auth success";
        }
        m_driver->deleteAllApplication(m_devHandle);
        ulReval = m_driver->createApplication(m_devHandle, m_pin, UKEY_APP_NAME, &m_appHandle);
        if (ulReval != SAR_OK)
        {
            KLOG_ERROR() << "create application failed:" << m_driver->getErrorReason(ulReval);
            return ulReval;
        }
        KLOG_DEBUG() << "create application suceess";
        ulReval = m_driver->createContainer(m_appHandle, m_pin, UKEY_CONTAINER_NAME, &m_retryCount, &m_containerHandle);
        if (ulReval != SAR_OK)
        {
            KLOG_ERROR() << "create container failed:" << m_driver->getErrorReason(ulReval);
            return ulReval;
        }
        KLOG_DEBUG() << "create new container success";
    }
    ulReval = m_driver->onOpenApplication(m_devHandle, (LPSTR)UKEY_APP_NAME, &m_appHandle);
    if (ulReval != SAR_OK)
    {
        KLOG_DEBUG() << "open Application failed:" << m_driver->getErrorReason(ulReval);
        return ulReval;
    }
    KLOG_DEBUG() << "open Application success";

    ulReval = m_driver->onOpenContainer(m_appHandle, m_pin, UKEY_CONTAINER_NAME, &m_retryCount, &m_containerHandle);
    if (ulReval != SAR_OK)
    {
        KLOG_ERROR() << "open container failed:" << m_driver->getErrorReason(ulReval);
        return ulReval;
    }
    KLOG_DEBUG() << "open container success";

    ulReval = m_driver->genECCKeyPair(m_containerHandle, publicKey);

    return ulReval;
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

void UKeyFTDevice::doingIdentifyStart(const QString &value)
{
    KLOG_DEBUG() << "ukey identify start";
    QJsonValue ukeyValue = Utils::getValueFromJsonString(value, AUTH_DEVICE_JSON_KEY_UKEY);
    auto jsonObject = ukeyValue.toObject();
    m_pin = jsonObject.value(AUTH_DEVICE_JSON_KEY_PIN).toString();
    if (m_pin.isEmpty())
    {
        QString message = tr("The pin code cannot be empty!");
        Q_EMIT m_dbusAdaptor->IdentifyStatus("", IDENTIFY_STATUS_NOT_MATCH, message);
        KLOG_ERROR() << message;
        internalStopIdentify();
        return;
    }

    QList<QByteArray> saveList;
    DeviceInfo deviceInfo = this->deviceInfo();
    if (m_identifyIDs.isEmpty())
    {
        saveList = FeatureDB::getInstance()->getFeatures(deviceInfo.idVendor, deviceInfo.idProduct, deviceType());
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
        closeUkey();
        m_pin.clear();
        setDeviceStatus(DEVICE_STATUS_IDLE);
        clearWatchedServices();
        KLOG_DEBUG() << "stop Enroll";
    }
}

void UKeyFTDevice::internalStopIdentify()
{
    if (deviceStatus() == DEVICE_STATUS_DOING_IDENTIFY)
    {
        closeUkey();
        m_identifyIDs.clear();
        m_pin.clear();
        setDeviceStatus(DEVICE_STATUS_IDLE);
        clearWatchedServices();
        KLOG_DEBUG() << "stopIdentify";
    }
}

void UKeyFTDevice::closeUkey()
{
    if (!m_driver->isLoaded())
    {
        return;
    }
    if (m_containerHandle)
    {
        m_driver->closeContainer(m_containerHandle);
        m_containerHandle = nullptr;
    }

    if (m_appHandle)
    {
        m_driver->closeApplication(m_appHandle);
        m_appHandle = nullptr;
    }

    if (m_devHandle)
    {
        m_driver->disConnectDev(m_devHandle);
        m_devHandle = nullptr;
    }
}

void UKeyFTDevice::identifyKeyFeature(QByteArray keyFeature)
{
    DEVHANDLE m_devHandle = m_driver->connectDev();
    if (!m_devHandle)
    {
        notifyUKeyIdentifyProcess(IDENTIFY_PROCESS_NO_MATCH);
        return;
    }

    ULONG ret;
    ret = m_driver->onOpenApplication(m_devHandle, (LPSTR)UKEY_APP_NAME, &m_appHandle);
    if (ret != SAR_OK)
    {
        notifyUKeyIdentifyProcess(IDENTIFY_PROCESS_NO_MATCH, ret);
        return;
    }

    ret = m_driver->onOpenContainer(m_appHandle, m_pin, UKEY_CONTAINER_NAME, &m_retryCount, &m_containerHandle);
    if (ret != SAR_OK)
    {
        notifyUKeyIdentifyProcess(IDENTIFY_PROCESS_NO_MATCH, ret);
        return;
    }

    ECCSIGNATUREBLOB Signature = {0};
    ret = m_driver->authSignData(m_containerHandle, m_devHandle, Signature);
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
        QString featureID = FeatureDB::getInstance()->getFeatureID(keyFeature);
        notifyUKeyIdentifyProcess(IDENTIFY_PROCESS_MACTCH, ret, featureID);
    }
}

void UKeyFTDevice::notifyUKeyEnrollProcess(EnrollProcess process, ULONG error, const QString &featureID)
{
    QString message, reason;
    // 目前只需要返回有关pin码的错误信息
    reason = getPinErrorReson(error);

    switch (process)
    {
    case ENROLL_PROCESS_SUCCESS:
        message = tr("Successed binding user");
        Q_EMIT m_dbusAdaptor->EnrollStatus(featureID, 100, ENROLL_STATUS_COMPLETE, message);
        break;
    case ENROLL_PROCESS_FAIL:
        message = tr("Binding user failed!");
        if (!reason.isEmpty())
        {
            message.append(reason);
        }
        Q_EMIT m_dbusAdaptor->EnrollStatus("", 0, ENROLL_STATUS_FAIL, message);
        KLOG_DEBUG() << "Ukey Error Reason:" << m_driver->getErrorReason(error);
        break;
    case ENROLL_PROCESS_REPEATED_ENROLL:
        message = tr("UKey has been bound");
        Q_EMIT m_dbusAdaptor->EnrollStatus("", 0, ENROLL_STATUS_REPEATED, message);
        Q_EMIT m_dbusAdaptor->EnrollStatus("", 0, ENROLL_STATUS_FAIL, message);
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
    reason = getPinErrorReson(error);

    switch (process)
    {
    case IDENTIFY_PROCESS_NO_MATCH:
        message = tr("identify fail!");
        // 目前只需要返回有关pin码的错误信息
        if (!reason.isEmpty())
        {
            message.append(reason);
        }
        message.append(QString(tr(",remaining retry count: %1")).arg(m_retryCount));
        Q_EMIT m_dbusAdaptor->IdentifyStatus("", IDENTIFY_STATUS_NOT_MATCH, message);
        break;
    case IDENTIFY_PROCESS_MACTCH:
        message = tr("identify ukey success");
        Q_EMIT m_dbusAdaptor->IdentifyStatus(featureID, IDENTIFY_STATUS_MATCH, message);
        break;
    default:
        break;
    }

    if (!message.isEmpty())
    {
        KLOG_DEBUG() << QString("%1, feature id:%2").arg(message).arg(featureID);
    }
}

QString UKeyFTDevice::getPinErrorReson(ULONG error)
{
    QString reason;
    if (error == SAR_OK)
    {
        return reason;
    }
    // 目前只需要返回有关pin码的错误信息
    switch (error)
    {
    case SAR_PIN_INCORRECT:
        reason = tr("pin incorrect");
        break;
    case SAR_PIN_LOCKED:
        reason = tr("pin locked");
        break;
    case SAR_PIN_INVALID:
        reason = tr("invalid pin");
        break;
    case SAR_PIN_LEN_RANGE:
        reason = tr("invalid pin length");
        break;
    default:
        break;
    }
    return reason;
}

}  // namespace Kiran
