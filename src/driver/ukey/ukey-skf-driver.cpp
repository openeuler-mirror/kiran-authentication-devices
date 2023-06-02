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
#include "ukey-skf-driver.h"
#include <dlfcn.h>
#include <qt5-log-i.h>
#include <QFile>
#include <QSettings>
#include "auth-enum.h"

namespace Kiran
{
// 签名者ID
#define CONF_DEFAULT_KEY_PUC_ID "PucId"
#define CONF_DEFAULT_KEY_DEV_KEY "DevKey"

#define CONF_DEFAULT_KEY_ADMIN_PINCODE "AdminPinCode"
#define CONF_DEFAULT_KEY_USER_PINCODE "UserPinCode"

#define SIGN_DATA "kiran-authentication-devices"

#define UKEY_DEFAULT_CONFIG "/etc/kiran-authentication-devices-sdk/ukey-skf.conf"
#define ADMIN_PIN_RETRY_COUNT 10
#define USER_PIN_RETRY_COUNT 10

extern "C"
{
    typedef ULONG (*SKF_EnumDev_Func)(BOOL bPresent, LPSTR szNameList, ULONG *pulSize);
    typedef ULONG (*SKF_ConnectDev_Func)(LPSTR szName, DEVHANDLE *phDev);
    typedef ULONG (*SKF_DisConnectDev_Func)(DEVHANDLE hDev);
    typedef ULONG (*SKF_GetDevState_Func)(LPSTR szDevName, ULONG *pulDevState);
    typedef ULONG (*SKF_GetDevInfo_Func)(DEVHANDLE hDev, DEVINFO *pDevInfo);
    typedef ULONG (*SKF_SetLabel_Func)(DEVHANDLE hDev, LPSTR szLabel);
    typedef ULONG (*SKF_OpenApplication_Func)(DEVHANDLE hDev, LPSTR szAppName, HAPPLICATION *phApplication);
    typedef ULONG (*SKF_VerifyPIN_Func)(HAPPLICATION hApplication, ULONG ulPINType, LPSTR szPIN, ULONG *pulRetryCount);
    typedef ULONG (*SKF_OpenContainer_Func)(HAPPLICATION hApplication, LPSTR szContainerName, HCONTAINER *phContainer);
    typedef ULONG (*SKF_GenECCKeyPair_Func)(HCONTAINER hContainer, ULONG ulAlgId, ECCPUBLICKEYBLOB *pBlob);
    typedef ULONG (*SKF_CloseContainer_Func)(HCONTAINER hContainer);
    typedef ULONG (*SKF_CloseApplication_Func)(HAPPLICATION hApplication);
    typedef ULONG (*SKF_CreateApplication_Func)(DEVHANDLE hDev, LPSTR szAppName, LPSTR szAdminPin,
                                                DWORD dwAdminPinRetryCount, LPSTR szUserPin, DWORD dwUserPinRetryCount,
                                                DWORD dwCreateFileRights, HAPPLICATION *phApplication);

    typedef ULONG (*SKF_EnumApplication_Func)(DEVHANDLE hDev, LPSTR szAppName, ULONG *pulSize);
    typedef ULONG (*SKF_ExportPublicKey_Func)(HCONTAINER hContainer, BOOL bSignFlag, BYTE *pbBlob, ULONG *pulBlobLen);
    typedef ULONG (*SKF_Digest_Func)(HANDLE hHash, BYTE *pbData, ULONG ulDataLen, BYTE *pbHashData, ULONG *pulHashLen);
    typedef ULONG (*SKF_DigestInit_Func)(DEVHANDLE hDev, ULONG ulAlgID, ECCPUBLICKEYBLOB *pPubKey,
                                         unsigned char *pucID, ULONG ulIDLen, HANDLE *phHash);
    typedef ULONG (*SKF_ECCSignData_Func)(HCONTAINER hContainer, BYTE *pbData, ULONG ulDataLen, PECCSIGNATUREBLOB pSignature);
    typedef ULONG (*SKF_ECCVerify_Func)(DEVHANDLE hDev, ECCPUBLICKEYBLOB *pECCPubKeyBlob, BYTE *pbData,
                                        ULONG ulDataLen, PECCSIGNATUREBLOB pSignature);

    typedef ULONG (*SKF_GenRandom_Func)(DEVHANDLE hDev, BYTE *pbRandom, ULONG ulRandomLen);
    typedef ULONG (*SKF_SetSymmKey_Func)(DEVHANDLE hDev, BYTE *pbKey, ULONG ulAlgID, HANDLE *phKey);
    typedef ULONG (*SKF_EncryptInit_Func)(HANDLE hKey, BLOCKCIPHERPARAM EncryptParam);
    typedef ULONG (*SKF_Encrypt_Func)(HANDLE hKey, BYTE *pbData, ULONG ulDataLen, BYTE *pbEncryptedData, ULONG *pulEncryptedLen);
    typedef ULONG (*SKF_DevAuth_Func)(DEVHANDLE hDev, BYTE *pbAuthData, ULONG ulLen);
    typedef ULONG (*SKF_DeleteApplication_Func)(DEVHANDLE hDev, LPSTR szAppName);
    typedef ULONG (*SKF_CreateContainer_Func)(HAPPLICATION hApplication, LPSTR szContainerName, HCONTAINER *phContainer);

    typedef ULONG (*SKF_ChangePIN_Func)(HAPPLICATION hApplication, ULONG ulPINType, LPSTR szOldPin, LPSTR szNewPin, ULONG *pulRetryCount);
    typedef ULONG (*SKF_UnblockPIN_Func)(HAPPLICATION hApplication, LPSTR szAdminPIN, LPSTR szNewUserPIN, ULONG *pulRetryCount);
}

struct SKFDriverLib
{
    SKF_EnumDev_Func SKF_EnumDev;
    SKF_ConnectDev_Func SKF_ConnectDev;
    SKF_DisConnectDev_Func SKF_DisConnectDev;
    SKF_GetDevState_Func SKF_GetDevState;
    SKF_GetDevInfo_Func SKF_GetDevInfo;
    SKF_SetLabel_Func SKF_SetLabel;
    SKF_OpenApplication_Func SKF_OpenApplication;
    SKF_VerifyPIN_Func SKF_VerifyPIN;
    SKF_OpenContainer_Func SKF_OpenContainer;
    SKF_GenECCKeyPair_Func SKF_GenECCKeyPair;
    SKF_CloseContainer_Func SKF_CloseContainer;
    SKF_CloseApplication_Func SKF_CloseApplication;
    SKF_CreateApplication_Func SKF_CreateApplication;
    SKF_EnumApplication_Func SKF_EnumApplication;
    SKF_ExportPublicKey_Func SKF_ExportPublicKey;
    SKF_Digest_Func SKF_Digest;
    SKF_DigestInit_Func SKF_DigestInit;
    SKF_ECCSignData_Func SKF_ECCSignData;
    SKF_ECCVerify_Func SKF_ECCVerify;
    SKF_GenRandom_Func SKF_GenRandom;
    SKF_SetSymmKey_Func SKF_SetSymmKey;
    SKF_EncryptInit_Func SKF_EncryptInit;
    SKF_Encrypt_Func SKF_Encrypt;
    SKF_DevAuth_Func SKF_DevAuth;
    SKF_DeleteApplication_Func SKF_DeleteApplication;
    SKF_CreateContainer_Func SKF_CreateContainer;
    SKF_ChangePIN_Func SKF_ChangePIN;
    SKF_UnblockPIN_Func SKF_UnblockPIN;

    void loadSym(HANDLE libHandle)
    {
        this->SKF_EnumDev = (SKF_EnumDev_Func)dlsym(libHandle, "SKF_EnumDev");
        this->SKF_ConnectDev = (SKF_ConnectDev_Func)dlsym(libHandle, "SKF_ConnectDev");
        this->SKF_DisConnectDev = (SKF_DisConnectDev_Func)dlsym(libHandle, "SKF_DisConnectDev");
        this->SKF_GetDevState = (SKF_GetDevState_Func)dlsym(libHandle, "SKF_GetDevState");
        this->SKF_GetDevInfo = (SKF_GetDevInfo_Func)dlsym(libHandle, "SKF_GetDevInfo");
        this->SKF_SetLabel = (SKF_SetLabel_Func)dlsym(libHandle, "SKF_SetLabel");
        this->SKF_OpenApplication = (SKF_OpenApplication_Func)dlsym(libHandle, "SKF_OpenApplication");
        this->SKF_VerifyPIN = (SKF_VerifyPIN_Func)dlsym(libHandle, "SKF_VerifyPIN");
        this->SKF_OpenContainer = (SKF_OpenContainer_Func)dlsym(libHandle, "SKF_OpenContainer");
        this->SKF_GenECCKeyPair = (SKF_GenECCKeyPair_Func)dlsym(libHandle, "SKF_GenECCKeyPair");
        this->SKF_CloseContainer = (SKF_CloseContainer_Func)dlsym(libHandle, "SKF_CloseContainer");
        this->SKF_CloseApplication = (SKF_CloseApplication_Func)dlsym(libHandle, "SKF_CloseApplication");
        this->SKF_CreateApplication = (SKF_CreateApplication_Func)dlsym(libHandle, "SKF_CreateApplication");
        this->SKF_EnumApplication = (SKF_EnumApplication_Func)dlsym(libHandle, "SKF_EnumApplication");
        this->SKF_ExportPublicKey = (SKF_ExportPublicKey_Func)dlsym(libHandle, "SKF_ExportPublicKey");
        this->SKF_Digest = (SKF_Digest_Func)dlsym(libHandle, "SKF_Digest");
        this->SKF_DigestInit = (SKF_DigestInit_Func)dlsym(libHandle, "SKF_DigestInit");
        this->SKF_ECCSignData = (SKF_ECCSignData_Func)dlsym(libHandle, "SKF_ECCSignData");
        this->SKF_ECCVerify = (SKF_ECCVerify_Func)dlsym(libHandle, "SKF_ECCVerify");
        this->SKF_GenRandom = (SKF_GenRandom_Func)dlsym(libHandle, "SKF_GenRandom");
        this->SKF_SetSymmKey = (SKF_SetSymmKey_Func)dlsym(libHandle, "SKF_SetSymmKey");
        this->SKF_EncryptInit = (SKF_EncryptInit_Func)dlsym(libHandle, "SKF_EncryptInit");
        this->SKF_Encrypt = (SKF_Encrypt_Func)dlsym(libHandle, "SKF_Encrypt");
        this->SKF_DevAuth = (SKF_DevAuth_Func)dlsym(libHandle, "SKF_DevAuth");
        this->SKF_DeleteApplication = (SKF_DeleteApplication_Func)dlsym(libHandle, "SKF_DeleteApplication");
        this->SKF_CreateContainer = (SKF_CreateContainer_Func)dlsym(libHandle, "SKF_CreateContainer");
        this->SKF_ChangePIN = (SKF_ChangePIN_Func)dlsym(libHandle, "SKF_ChangePIN");
        this->SKF_UnblockPIN = (SKF_UnblockPIN_Func)dlsym(libHandle, "SKF_UnblockPIN");

        this->isLoaded = true;
    }

    bool isLoaded = false;
};

UKeySKFDriver::UKeySKFDriver(QObject *parent) : QObject(parent),
                                                m_libHandle(nullptr)
{
    m_driverLib = QSharedPointer<SKFDriverLib>(new SKFDriverLib);
}

UKeySKFDriver::~UKeySKFDriver()
{
    if (m_libHandle)
    {
        dlclose(m_libHandle);
        m_libHandle = NULL;
    }
}

bool UKeySKFDriver::loadLibrary(QString libPath)
{
    if (!QFile::exists(UKEY_DEFAULT_CONFIG))
    {
        KLOG_ERROR() << "ukey-skf.conf not found";
        return false;
    }

    m_libHandle = dlopen(libPath.toStdString().c_str(), RTLD_NOW);
    if (m_libHandle == nullptr)
    {
        KLOG_ERROR() << "Load ukey lib failed,error:" << dlerror();
        return false;
    }

    m_driverLib->loadSym(m_libHandle);

    return true;
}

bool UKeySKFDriver::isLoaded()
{
    return m_driverLib->isLoaded;
}

QStringList UKeySKFDriver::enumDevName()
{
    ULONG ulBufSize = 0;
    ULONG ulReval = m_driverLib->SKF_EnumDev(TRUE, NULL, &ulBufSize);
    if (ulReval != SAR_OK)
    {
        KLOG_DEBUG() << "Enum Dev error:" << getErrorReason(ulReval);
        return QStringList();
    }

    LPSTR szNameList = (LPSTR)malloc(ulBufSize * sizeof(CHAR));
    memset(szNameList, '\0', ulBufSize);
    ulReval = m_driverLib->SKF_EnumDev(TRUE, szNameList, &ulBufSize);
    if ((ulReval != SAR_OK))
    {
        KLOG_DEBUG() << "Enum Dev error:" << getErrorReason(ulReval);
        free(szNameList);
        return QStringList();
    }

    LPSTR pszTemp = szNameList;
    if (NULL == pszTemp)
    {
        KLOG_DEBUG() << "no found ukey device";
        free(szNameList);
        return QStringList();
    }

    QStringList nameList;
    while ((*pszTemp != '\0') && (*(pszTemp + 1) != '\0'))
    {
        nameList << QString::fromLatin1((const char *)pszTemp, strlen((const char *)pszTemp));
        pszTemp += strlen((const char *)pszTemp) + 1;
    }
    KLOG_DEBUG() << "device name list:" << nameList;

    free(szNameList);
    return nameList;
}

QStringList UKeySKFDriver::enumDevSerialNumber()
{
    QStringList devNameList = enumDevName();
    QStringList serialNumberList;
    for (auto devName : devNameList)
    {
        DEVHANDLE devHandle;
        ULONG pulDevState;
        QByteArray devNameArray = devName.toLatin1();
        unsigned char *szDevName = (unsigned char *)devNameArray.data();
        ULONG ulReval = m_driverLib->SKF_ConnectDev(szDevName, &devHandle);
        if (SAR_OK != ulReval)
        {
            continue;
        }
        DEVINFO devInfo;
        m_driverLib->SKF_GetDevInfo(devHandle, &devInfo);
        serialNumberList << QString((const char *)devInfo.SerialNumber);
        m_driverLib->SKF_DisConnectDev(devHandle);
    }
    KLOG_DEBUG() << "dev serial number list:" << serialNumberList;
    return serialNumberList;
}

DEVHANDLE UKeySKFDriver::connectDev()
{
    QStringList devNameList = enumDevName();
    for (auto devName : devNameList)
    {
        DEVHANDLE devHandle;
        ULONG pulDevState;
        QByteArray devNameArray = devName.toLatin1();
        unsigned char *szDevName = (unsigned char *)devNameArray.data();
        ULONG ulReval = m_driverLib->SKF_ConnectDev(szDevName, &devHandle);
        if (SAR_OK == ulReval)
        {
            KLOG_DEBUG() << "connect dev success";
            return devHandle;
        }
        else
        {
            KLOG_ERROR() << "Connect Dev failed:" << getErrorReason(ulReval);
        }
    }

    return nullptr;
}

DEVHANDLE UKeySKFDriver::connectDev(const QString &serialNumber)
{
    QStringList devNameList = enumDevName();
    for (auto devName : devNameList)
    {
        DEVHANDLE devHandle;
        QByteArray devNameArray = devName.toLatin1();
        unsigned char *szDevName = (unsigned char *)devNameArray.data();
        ULONG ulReval = m_driverLib->SKF_ConnectDev(szDevName, &devHandle);
        if (ulReval != SAR_OK)
        {
            KLOG_ERROR() << QString("Connect Dev %1 failed:").arg(devName) << getErrorReason(ulReval);
            continue;
        }

        DEVINFO devInfo;
        m_driverLib->SKF_GetDevInfo(devHandle, &devInfo);
        if (serialNumber == QString((const char *)devInfo.SerialNumber))
        {
            KLOG_DEBUG() << QString("Connect Dev %1 success, SerialNumber: %2").arg(devName).arg(serialNumber);
            return devHandle;
        }
        else
        {
            m_driverLib->SKF_DisConnectDev(devHandle);
        }
    }
    return nullptr;
}

void UKeySKFDriver::deleteAllApplication(DEVHANDLE devHandle)
{
    ULONG ulReval = SAR_FAIL;
    char szAppNames[256] = {0};
    ULONG ulSize = 256;

    ulReval = m_driverLib->SKF_EnumApplication(devHandle, (LPSTR)szAppNames, &ulSize);
    if (SAR_OK == ulReval)
    {
        char *pszTemp = szAppNames;
        if (*pszTemp == '\0')
        {
            m_driverLib->SKF_DeleteApplication(devHandle, (LPSTR)pszTemp);
        }

        while (*pszTemp != '\0')
        {
            m_driverLib->SKF_DeleteApplication(devHandle, (LPSTR)pszTemp);
            pszTemp += strlen((const char *)pszTemp) + 1;
        }
    }
    KLOG_DEBUG() << "clear all application";
}

QString UKeySKFDriver::enumApplication(DEVHANDLE devHandle)
{
    char szAppNames[256] = {0};
    ULONG ulSize = 256;
    ULONG ret = m_driverLib->SKF_EnumApplication(devHandle, (LPSTR)szAppNames, &ulSize);
    if (ret == SAR_OK)
    {
        QString appNames(szAppNames);
        KLOG_DEBUG() << "enum app names:" << appNames;
        return appNames;
    }
    else
    {
        return QString();
    }
}

bool UKeySKFDriver::isExistPublicKey(HCONTAINER containerHandle)
{
    unsigned char *pPubKey = NULL;
    ULONG ulPubKeyLen = 0;
    ULONG ret = m_driverLib->SKF_ExportPublicKey(containerHandle, TRUE, pPubKey, &ulPubKeyLen);
    pPubKey = (unsigned char *)malloc(ulPubKeyLen);
    ret = m_driverLib->SKF_ExportPublicKey(containerHandle, TRUE, pPubKey, &ulPubKeyLen);
    if (ret == SAR_OK)
    {
        return true;
    }
    else
    {
        return false;
    }
}

ULONG UKeySKFDriver::devAuth(DEVHANDLE devHandle)
{
    BYTE random[16] = {0};
    BYTE devKey[16] = {0};
    BLOCKCIPHERPARAM param = {0};
    BYTE devkeyenc[16] = {0};
    ULONG dwResultLen = 16;
    ULONG ulReval;
    DEVINFO devInfo;
    HANDLE hSessionKey;

    QString defaultDevKey = getDefaultValueFromConf(CONF_DEFAULT_KEY_DEV_KEY);
    QByteArray byteArray = defaultDevKey.toLatin1();
    unsigned char *key = (unsigned char *)byteArray.data();

    memcpy(devKey, key, 16);

    ulReval = m_driverLib->SKF_GenRandom(devHandle, random, 8);
    if (SAR_OK != ulReval)
        return ulReval;

    ulReval = m_driverLib->SKF_GetDevInfo(devHandle, &devInfo);
    if (SAR_OK != ulReval)
        return ulReval;

    ulReval = m_driverLib->SKF_SetSymmKey(devHandle, devKey, devInfo.DevAuthAlgId, &hSessionKey);
    if (SAR_OK != ulReval)
        return ulReval;

    ulReval = m_driverLib->SKF_EncryptInit(hSessionKey, param);
    if (SAR_OK != ulReval)
        return ulReval;

    ulReval = m_driverLib->SKF_Encrypt(hSessionKey, random, 16, devkeyenc, &dwResultLen);
    if (SAR_OK != ulReval)
        return ulReval;

    ulReval = m_driverLib->SKF_DevAuth(devHandle, devkeyenc, 16);

    return ulReval;
}

ULONG UKeySKFDriver::onOpenApplication(DEVHANDLE devHandle, LPSTR szAppName, HAPPLICATION *appHandle)
{
    ULONG ret = m_driverLib->SKF_OpenApplication(devHandle, szAppName, appHandle);
    return ret;
}

ULONG UKeySKFDriver::onOpenContainer(HAPPLICATION appHandle, const QString &pin, QString containerName, ULONG *retryCount, HCONTAINER *containerHandle)
{
    QByteArray byteArray = pin.toLatin1();
    unsigned char *szPIN = (unsigned char *)byteArray.data();
    ULONG ret = m_driverLib->SKF_VerifyPIN(appHandle, USER_TYPE, szPIN, retryCount);
    if (ret != SAR_OK)
    {
        KLOG_DEBUG() << "Verify PIN failed:" << getErrorReason(ret);
        KLOG_DEBUG() << "Retry Count:" << retryCount;
        return ret;
    }

    QByteArray containerNameArray = containerName.toLatin1();
    unsigned char *szContainerName = (unsigned char *)containerNameArray.data();

    ret = m_driverLib->SKF_OpenContainer(appHandle, szContainerName, containerHandle);
    return ret;
}

void UKeySKFDriver::closeApplication(HAPPLICATION appHandle)
{
    m_driverLib->SKF_CloseApplication(appHandle);
}
void UKeySKFDriver::closeContainer(HCONTAINER containerHandle)
{
    m_driverLib->SKF_CloseContainer(containerHandle);
}

void UKeySKFDriver::disConnectDev(DEVHANDLE devHandle)
{
    ULONG ret = m_driverLib->SKF_DisConnectDev(devHandle);
    KLOG_DEBUG() << "getErrorReason(ret):" << getErrorReason(ret);
}

ULONG UKeySKFDriver::createApplication(DEVHANDLE devHandle, QString pin, QString appName, HAPPLICATION *appHandle)
{
    QByteArray pinArray = pin.toLatin1();
    unsigned char *userPin = (unsigned char *)pinArray.data();

    QByteArray appNameArray = appName.toLatin1();
    unsigned char *szAppName = (unsigned char *)appNameArray.data();

    QString defaultAdminPin = getDefaultValueFromConf(CONF_DEFAULT_KEY_ADMIN_PINCODE);
    QByteArray byteArray = defaultAdminPin.toLatin1();
    unsigned char *adminPIn = (unsigned char *)byteArray.data();

    ULONG ulReval = m_driverLib->SKF_CreateApplication(devHandle, szAppName, adminPIn,
                                                       ADMIN_PIN_RETRY_COUNT, userPin, USER_PIN_RETRY_COUNT,
                                                       SECURE_USER_ACCOUNT, appHandle);
    return ulReval;
}

ULONG UKeySKFDriver::createContainer(HAPPLICATION appHandle, QString pin, QString containerName, ULONG *retryCount, HCONTAINER *containerHandle)
{
    QByteArray byteArray = pin.toLatin1();
    unsigned char *userPin = (unsigned char *)byteArray.data();
    ULONG ulReval = m_driverLib->SKF_VerifyPIN(appHandle, USER_TYPE, userPin, retryCount);
    if (ulReval != SAR_OK)
    {
        return ulReval;
    }

    QByteArray containerNameArray = containerName.toLatin1();
    unsigned char *szContainerName = (unsigned char *)containerNameArray.data();
    ulReval = m_driverLib->SKF_CreateContainer(appHandle, szContainerName, containerHandle);
    return ulReval;
}

ULONG UKeySKFDriver::genECCKeyPair(HCONTAINER containerHandle, ECCPUBLICKEYBLOB *pBlob)
{
    return m_driverLib->SKF_GenECCKeyPair(containerHandle, SGD_SM2_1, pBlob);
}

ULONG UKeySKFDriver::authSignData(HCONTAINER containerHandle, DEVHANDLE devHandle, ECCSIGNATUREBLOB &Signature)
{
    unsigned char *pPubKey = NULL;
    ULONG ulPubKeyLen = 0;
    ECCPUBLICKEYBLOB EccPubKey = {0};
    unsigned char pucId[32] = {0};
    ULONG ulIdLen = 16;
    HANDLE hHash = nullptr;
    ULONG ulHashLen = 64;
    int signDataLen = strlen(SIGN_DATA);
    unsigned char pbHashData[33] = {0};

    QString defaultPucId = getDefaultValueFromConf(CONF_DEFAULT_KEY_PUC_ID);
    QByteArray byteArray = defaultPucId.toLatin1();
    unsigned char *PUC_ID = (unsigned char *)byteArray.data();

    ULONG ret = m_driverLib->SKF_ExportPublicKey(containerHandle, TRUE, pPubKey, &ulPubKeyLen);
    if (ret != SAR_OK)
    {
        goto end;
    }

    pPubKey = (unsigned char *)malloc(ulPubKeyLen);
    if (pPubKey == NULL)
    {
        goto end;
    }

    ret = m_driverLib->SKF_ExportPublicKey(containerHandle, TRUE, pPubKey, &ulPubKeyLen);
    if (ret != SAR_OK)
    {
        goto end;
    }

    if (ulPubKeyLen != sizeof(ECCPUBLICKEYBLOB))
    {
        goto end;
    }

    memcpy(&EccPubKey, pPubKey, ulPubKeyLen);
    memcpy(pucId, PUC_ID, 16);

    ret = m_driverLib->SKF_DigestInit(devHandle, SGD_SM3, &EccPubKey, pucId, ulIdLen, &hHash);
    if (ret != SAR_OK)
    {
        goto end;
    }

    ret = m_driverLib->SKF_Digest(hHash, (BYTE *)SIGN_DATA, signDataLen, pbHashData, &ulHashLen);
    if (ret != SAR_OK)
    {
        goto end;
    }

    ret = m_driverLib->SKF_ECCSignData(containerHandle, pbHashData, ulHashLen, &Signature);

end:
    getErrorReason(ret);
    return ret;
}

ULONG UKeySKFDriver::verifyData(DEVHANDLE devHandle, ECCSIGNATUREBLOB &Signature, ECCPUBLICKEYBLOB &publicKey)
{
    unsigned char *pbInData = NULL, pbHashData[33] = {0}, pbOutData[256] = {0};
    ULONG ulInLen = 0, ulOutLen = 0, ulHashLen = 0, ulIdLen = 7;
    unsigned char pucId[32] = {0};
    HANDLE hHash;
    ULONG ulPubKeyLen = 0;
    int signDataLen = strlen(SIGN_DATA);
    QString defaultPucId = getDefaultValueFromConf(CONF_DEFAULT_KEY_PUC_ID);
    QByteArray byteArray = defaultPucId.toLatin1();
    unsigned char *PUC_ID = (unsigned char *)byteArray.data();

    memcpy(pucId, PUC_ID, 16);
    ulIdLen = 16;
    ULONG ulReval = m_driverLib->SKF_DigestInit(devHandle, SGD_SM3, &publicKey, pucId, ulIdLen, &hHash);
    if (ulReval != SAR_OK)
    {
        goto end;
    }

    ulHashLen = 64;
    ulReval = m_driverLib->SKF_Digest(hHash, (BYTE *)SIGN_DATA, signDataLen, pbHashData, &ulHashLen);
    if (ulReval != SAR_OK)
    {
        goto end;
    }

    ulReval = m_driverLib->SKF_ECCVerify(devHandle, &publicKey, pbHashData, ulHashLen, &Signature);

end:
    getErrorReason(ulReval);
    return ulReval;
}

ULONG UKeySKFDriver::changePin(DEVHANDLE devHandle, int userType, const QString &currentPin, const QString &newPin, ULONG *retryCount)
{
    HAPPLICATION appHandle = nullptr;
    ULONG ulReval = onOpenApplication(devHandle, (LPSTR)UKEY_APP_NAME, &appHandle);
    if (ulReval != SAR_OK)
    {
        KLOG_DEBUG() << "open Application failed:" << getErrorReason(ulReval);
        return ulReval;
    }
    KLOG_DEBUG() << "open Application success";

    QByteArray currentPinArray = currentPin.toLatin1();
    unsigned char *szCurrentPIN = (unsigned char *)currentPinArray.data();

    QByteArray newPinArray = newPin.toLatin1();
    unsigned char *szNewPIN = (unsigned char *)newPinArray.data();

    if (userType == ADMIN_TYPE)
    {
        ulReval = m_driverLib->SKF_ChangePIN(appHandle, ADMIN_TYPE, szCurrentPIN, szNewPIN, retryCount);
    }
    else if (userType == USER_TYPE)
    {
        ulReval = m_driverLib->SKF_ChangePIN(appHandle, USER_TYPE, szCurrentPIN, szNewPIN, retryCount);
    }

    return ulReval;
}

ULONG UKeySKFDriver::unblockPin(DEVHANDLE devHandle, const QString &adminPin, const QString &newUserPin, ULONG *retryCount)
{
    HAPPLICATION appHandle = nullptr;
    ULONG ulReval = onOpenApplication(devHandle, (LPSTR)UKEY_APP_NAME, &appHandle);
    if (ulReval != SAR_OK)
    {
        KLOG_DEBUG() << "open Application failed:" << getErrorReason(ulReval);
        return ulReval;
    }
    KLOG_DEBUG() << "open Application success";

    QByteArray adminPinArray = adminPin.toLatin1();
    unsigned char *szAdminPin = (unsigned char *)adminPinArray.data();

    QByteArray newUserPinArray = newUserPin.toLatin1();
    unsigned char *szNewUserPIN = (unsigned char *)newUserPinArray.data();

    ulReval = m_driverLib->SKF_UnblockPIN(appHandle, szAdminPin, szNewUserPIN, retryCount);
    return ulReval;
}

ULONG UKeySKFDriver::resetUkey(DEVHANDLE devHandle)
{
    ULONG ulReval = devAuth(devHandle);
    if (ulReval != SAR_OK)
    {
        KLOG_ERROR() << "Device authentication failed";
        return ulReval;
    }
    deleteAllApplication(devHandle);
    return ulReval;
}

QString UKeySKFDriver::getErrorReason(ULONG error)
{
    for (int i = 0; i < sizeof(skf_errors) / sizeof(skf_errors[0]); i++)
    {
        if (error == skf_errors[i].err)
        {
            return skf_errors[i].reason;
        }
    }
    return QString();
}

QString UKeySKFDriver::getDefaultValueFromConf(const QString &key)
{
    QSettings confSettings(UKEY_DEFAULT_CONFIG, QSettings::NativeFormat);
    QVariant value = confSettings.value(QString("default/%1").arg(key));
    return value.toString();
}

}  // namespace Kiran
