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
QStringList UKeyFTDevice::m_existingSerialNumber;

UKeyFTDevice::UKeyFTDevice(QObject *parent) : AuthDevice{parent}
{
    setDeviceType(DEVICE_TYPE_UKey);
    setDeviceDriver(FT_UKEY_DRIVER_LIB);
    /**
     * NOTE:
     * UKey设备插入时，设备可能处在未准备好的状态，无法获取到serialNumber
     * 如果初始化时，未获取到serialNumber，则开启定时器再次获取
     */
    if (!initSerialNumber())
    {
        m_reInitSerialNumberTimer.start(1000);
    }
    connect(&m_reInitSerialNumberTimer, &QTimer::timeout, this, &UKeyFTDevice::initSerialNumber);
}

UKeyFTDevice::~UKeyFTDevice()
{
    int index = m_existingSerialNumber.indexOf(deviceSerialNumber());
    m_existingSerialNumber.removeAt(index);
    KLOG_DEBUG() << "destory device, serialNumber:" << deviceSerialNumber();
}

bool UKeyFTDevice::initDriver()
{
    return true;
}

bool UKeyFTDevice::initSerialNumber()
{
    UKeySKFDriver driver;
    driver.loadLibrary(FT_UKEY_DRIVER_LIB);
    QStringList serialNumberList = driver.enumDevSerialNumber();
    for (auto serialNumber : serialNumberList)
    {
        if (m_existingSerialNumber.contains(serialNumber))
        {
            continue;
        }
        setDeviceSerialNumber(serialNumber);
        m_existingSerialNumber << serialNumber;
        break;
    }
    KLOG_DEBUG() << "init serial number:" << deviceSerialNumber();
    if (deviceSerialNumber().isEmpty())
    {
        return false;
    }
    else
    {
        m_reInitSerialNumberTimer.stop();
        return true;
    }
}

void UKeyFTDevice::doingEnrollStart(const QString &extraInfo)
{
    KLOG_DEBUG() << "ukey enroll start";
    QJsonValue ukeyValue = Utils::getValueFromJsonString(extraInfo, AUTH_DEVICE_JSON_KEY_UKEY);
    auto jsonObject = ukeyValue.toObject();
    QString pin = jsonObject.value(AUTH_DEVICE_JSON_KEY_PIN).toString();
    HANDLE devHandle = nullptr;

    KLOG_DEBUG() << "device serial number:" << deviceSerialNumber();
    if (pin.isEmpty())
    {
        QString message = tr("The pin code cannot be empty!");
        Q_EMIT m_dbusAdaptor->EnrollStatus("", 0, ENROLL_STATUS_FAIL, message);
        KLOG_ERROR() << "The pin code cannot be empty!";
        goto end;
    }

    if (isExistBinding())
    {
        notifyUKeyEnrollProcess(ENROLL_PROCESS_REPEATED_ENROLL);
        goto end;
    }

    m_driver = new UKeySKFDriver();
    if (!m_driver->loadLibrary(FT_UKEY_DRIVER_LIB))
    {
        KLOG_ERROR() << "load library failed";
        notifyUKeyEnrollProcess(ENROLL_PROCESS_FAIL);
        goto end;
    }

    devHandle = m_driver->connectDev(deviceSerialNumber());
    KLOG_DEBUG() << "devHandle:" << devHandle;
    if (!devHandle)
    {
        KLOG_ERROR() << "Connect Dev failed";
        notifyUKeyEnrollProcess(ENROLL_PROCESS_FAIL);
        goto end;
    }
    bindingUKey(devHandle,pin);
    m_driver->disConnectDev(devHandle);

end:
    internalStopEnroll();
    return;
}

void UKeyFTDevice::bindingUKey(DEVHANDLE devHandle, const QString &pin)
{
    HCONTAINER containerHandle;
    HAPPLICATION appHandle;
    ULONG ret = createContainer(pin, devHandle, &appHandle, &containerHandle);
    if (ret != SAR_OK)
    {
        KLOG_ERROR() << "create container failed:" << m_driver->getErrorReason(ret);
        notifyUKeyEnrollProcess(ENROLL_PROCESS_FAIL, ret);
        m_driver->closeContainer(containerHandle);
        m_driver->closeApplication(appHandle);
        return;
    }
    KLOG_DEBUG() << "create container success";

    ECCPUBLICKEYBLOB publicKey = {0};
    ret = m_driver->genECCKeyPair(containerHandle, &publicKey);
    if (ret != SAR_OK)
    {
        KLOG_ERROR() << "gen ecc key pair failed:" << m_driver->getErrorReason(ret);
        notifyUKeyEnrollProcess(ENROLL_PROCESS_FAIL, ret);
        m_driver->closeContainer(containerHandle);
        m_driver->closeApplication(appHandle);
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

    if (FeatureDB::getInstance()->addFeature(featureID, keyFeature, deviceInfo, deviceType(), deviceSerialNumber()))
    {
        notifyUKeyEnrollProcess(ENROLL_PROCESS_SUCCESS, SAR_OK, featureID);
    }
    else
    {
        KLOG_ERROR() << "save feature fail";
        notifyUKeyEnrollProcess(ENROLL_PROCESS_FAIL);
    }

    m_driver->closeContainer(containerHandle);
    m_driver->closeApplication(appHandle);
}

ULONG UKeyFTDevice::createContainer(const QString &pin, DEVHANDLE devHandle, HAPPLICATION *appHandle, HCONTAINER *containerHandle)
{
    // NOTE:必须通过设备认证后才能在设备内创建和删除应用
    ULONG ulReval = m_driver->devAuth(devHandle);
    if (ulReval != SAR_OK)
    {
        KLOG_ERROR() << "Device auth failure: " << m_driver->getErrorReason(ulReval);
        return ulReval;
    }
    KLOG_DEBUG() << "device auth success";
    m_driver->deleteAllApplication(devHandle);

    ulReval = m_driver->createApplication(devHandle, pin, UKEY_APP_NAME, appHandle);
    if (ulReval != SAR_OK)
    {
        KLOG_ERROR() << "create application failed:" << m_driver->getErrorReason(ulReval)
                     << " device serial number:" << deviceSerialNumber();
        return ulReval;
    }
    KLOG_DEBUG() << "create application suceess";
    ulReval = m_driver->createContainer(*appHandle, pin, UKEY_CONTAINER_NAME, &m_retryCount, containerHandle);
    return ulReval;
}

bool UKeyFTDevice::isExistBinding()
{
    QStringList featureIDs = FeatureDB::getInstance()->getFeatureIDs(deviceInfo().idVendor, deviceInfo().idProduct, deviceType(), deviceSerialNumber());
    for (auto id : featureIDs)
    {
        FeatureInfo info = FeatureDB::getInstance()->getFeatureInfo(id);
        if (info.deviceSerialNumber == deviceSerialNumber())
        {
            KLOG_DEBUG() << QString("Exist Binding: feature id:%1, device serial number: %2").arg(id).arg(deviceSerialNumber());
            return true;
        }
    }
    return false;
}

bool UKeyFTDevice::isExistsApplication(DEVHANDLE devHandle, const QString &appName)
{
    QString appNames = m_driver->enumApplication(devHandle);
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
    QString pin = jsonObject.value(AUTH_DEVICE_JSON_KEY_PIN).toString();
    if (pin.isEmpty())
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
        saveList = FeatureDB::getInstance()->getFeatures(deviceInfo.idVendor, deviceInfo.idProduct, deviceType(), deviceSerialNumber());
    }
    else
    {
        Q_FOREACH (auto id, m_identifyIDs)
        {
            QByteArray feature = FeatureDB::getInstance()->getFeature(id);
            saveList << feature;
        }
    }

    if (saveList.count() == 0)
    {
        KLOG_DEBUG() << "no found feature id";
        notifyUKeyIdentifyProcess(IDENTIFY_PROCESS_NO_MATCH);
        internalStopIdentify();
        return;
    }

    m_driver = new UKeySKFDriver();
    if (!m_driver->loadLibrary(FT_UKEY_DRIVER_LIB))
    {
        KLOG_ERROR() << "load library failed";
        notifyUKeyEnrollProcess(ENROLL_PROCESS_FAIL);
        internalStopIdentify();
        return;
    }

    for (int j = 0; j < saveList.count(); j++)
    {
        auto savedKey = saveList.value(j);
        identifyKeyFeature(pin,savedKey);
    }

    internalStopIdentify();
}

void UKeyFTDevice::internalStopEnroll()
{
    if (deviceStatus() == DEVICE_STATUS_DOING_ENROLL)
    {
        setDeviceStatus(DEVICE_STATUS_IDLE);
        clearWatchedServices();
        if (m_driver)
        {
            KLOG_DEBUG() << "delete m_driver";
            delete m_driver;
            m_driver = nullptr;
        }
        KLOG_DEBUG() << "stop Enroll";
    }
}

void UKeyFTDevice::internalStopIdentify()
{
    if (deviceStatus() == DEVICE_STATUS_DOING_IDENTIFY)
    {
        m_identifyIDs.clear();
        setDeviceStatus(DEVICE_STATUS_IDLE);
        clearWatchedServices();
        if (m_driver)
        {
            delete m_driver;
            m_driver = nullptr;
        }
        KLOG_DEBUG() << "stopIdentify";
    }
}

void UKeyFTDevice::resetUkey()
{
    UKeySKFDriver driver;
    driver.loadLibrary(FT_UKEY_DRIVER_LIB);
    DEVHANDLE devHandle = driver.connectDev(deviceSerialNumber());
    driver.resetUkey(devHandle);
    KLOG_DEBUG() << "resetUkey";
}

void UKeyFTDevice::identifyKeyFeature(const QString &pin, QByteArray keyFeature)
{
    DEVHANDLE devHandle = m_driver->connectDev(deviceSerialNumber());
    if (!devHandle)
    {
        notifyUKeyIdentifyProcess(IDENTIFY_PROCESS_NO_MATCH);
        return;
    }

    ULONG ret;
    HAPPLICATION appHandle;
    HCONTAINER containerHandle;

    ret = m_driver->onOpenApplication(devHandle, (LPSTR)UKEY_APP_NAME, &appHandle);
    if (ret != SAR_OK)
    {
        notifyUKeyIdentifyProcess(IDENTIFY_PROCESS_NO_MATCH, ret);
        return;
    }

    ret = m_driver->onOpenContainer(appHandle, pin, UKEY_CONTAINER_NAME, &m_retryCount, &containerHandle);
    if (ret != SAR_OK)
    {
        notifyUKeyIdentifyProcess(IDENTIFY_PROCESS_NO_MATCH, ret);
        return;
    }

    ECCSIGNATUREBLOB Signature = {0};
    ret = m_driver->authSignData(containerHandle, devHandle, Signature);
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

    ret = m_driver->verifyData(devHandle, Signature, eccPubKey);
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
    QString reason;
    // 目前只需要返回有关pin码的错误信息
    reason = getPinErrorReson(error);
    if (error != SAR_OK)
    {
        KLOG_DEBUG() << "Ukey Error Reason:" << m_driver->getErrorReason(error);
    }

    QString message = tr("Binding user failed!");
    switch (process)
    {
    case ENROLL_PROCESS_SUCCESS:
        message = tr("Successed binding user");
        Q_EMIT m_dbusAdaptor->EnrollStatus(featureID, 100, ENROLL_STATUS_COMPLETE, message);
        break;
    case ENROLL_PROCESS_FAIL:
        if (!reason.isEmpty())
        {
            message.append(reason);
        }
        Q_EMIT m_dbusAdaptor->EnrollStatus("", 0, ENROLL_STATUS_FAIL, message);
        break;
    case ENROLL_PROCESS_REPEATED_ENROLL:
        message.append(tr("UKey has been bound"));
        Q_EMIT m_dbusAdaptor->EnrollStatus("", 0, ENROLL_STATUS_FAIL, message);
        break;
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
