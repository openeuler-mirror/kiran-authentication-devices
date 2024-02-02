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

#include "fp-za-driver.h"
#include <dlfcn.h>
#include <qt5-log-i.h>
#include <cstring>
#include "SYProtocol.h"
#include "auth-enum.h"
#include "driver/driver-factory.h"

namespace Kiran
{
extern "C"
{
    // libzaz.so
    typedef int (*T_ZAZ_MODE)(int mode);
    typedef int (*T_ZAZ_SETPATH)(int fptype, int path);
    typedef void (*T_ZAZ_Delaytime)(int times);
    typedef int (*T_ZAZOpenDeviceEx)(HANDLE* hHandle, int nDeviceType, const char* nPortNum, int nPortPara, int nPackageSize);
    typedef int (*T_ZAZCloseDeviceEx)(HANDLE hHandle);
    typedef int (*T_ZAZVfyPwd)(HANDLE hHandle, int nAddr, unsigned char* pPassword);
    typedef int (*T_ZAZGetImage)(HANDLE hHandle, int nAddr);
    typedef int (*T_ZAZGenChar)(HANDLE hHandle, int nAddr, int iBufferID);
    typedef int (*T_ZAZMatch)(HANDLE hHandle, int nAddr, int* iScore);
    typedef int (*T_ZAZSearch)(HANDLE hHandle, int nAddr, int iBufferID, int iStartPage, int iPageNum, int* iMbAddress, int* iscore);

    typedef int (*T_ZAZRegModule)(HANDLE hHandle, int nAddr);
    typedef int (*T_ZAZStoreChar)(HANDLE hHandle, int nAddr, int iBufferID, int iPageID);
    typedef int (*T_ZAZDelChar)(HANDLE hHandle, int nAddr, int iStartPageID, int nDelPageNum);
    typedef int (*T_ZAZEmpty)(HANDLE hHandle, int nAddr);
    typedef int (*T_ZAZReadParTable)(HANDLE hHandle, int nAddr, unsigned char* pParTable);

    typedef int (*T_ZAZTemplateNum)(HANDLE hHandle, int nAddr, int* iMbNum);
    typedef int (*T_ZAZGetRandomData)(HANDLE hHandle, int nAddr, unsigned char* pRandom);
    typedef int (*T_ZAZReadIndexTable)(HANDLE hHandle, int nAddr, int nPage, unsigned char* UserContent);
    typedef int (*T_ZAZDoUserDefine)(HANDLE hHandle, int nAddr, int GPIO, int STATE);
    typedef int (*T_ZAZSetCharLen)(int nLen);
    typedef int (*T_ZAZSetImgLen)(int w, int h);
    typedef int (*T_ZAZGetCharLen)(int* pnLen);
    typedef int (*T_ZAZLoadChar)(HANDLE hHandle, int nAddr, int iBufferID, int iPageID);
    typedef int (*T_ZAZUpChar)(HANDLE hHandle, int nAddr, int iBufferID, unsigned char* pTemplet, int* iTempletLength);
    typedef int (*T_ZAZDownChar)(HANDLE hHandle, int nAddr, int iBufferID, unsigned char* pTemplet, int iTempletLength);
    typedef int (*T_ZAZUpImage)(HANDLE hHandle, int nAddr, unsigned char* pImageData, int* iImageLength);
    typedef int (*T_ZAZDownImage)(HANDLE hHandle, int nAddr, unsigned char* pImageData, int iLength);
    typedef int (*T_ZAZImgData2BMP)(unsigned char* pImgData, const char* pImageFile);
    typedef int (*T_ZAZGetImgDataFromBMP)(const char* pImageFile, unsigned char* pImageData, int* pnImageLen);
    typedef int (*T_ZAZReadInfo)(HANDLE hHandle, int nAddr, int nPage, unsigned char* UserContent);
    typedef int (*T_ZAZWriteInfo)(HANDLE hHandle, int nAddr, int nPage, unsigned char* UserContent);
    typedef int (*T_ZAZSetPwd)(HANDLE hHandle, int nAddr, unsigned char* pPassword);
    typedef int (*T_ZAZReadInfPage)(HANDLE hHandle, int nAddr, unsigned char* pInf);
    typedef int (*T_ZAZGetImgQuality)(int width, int height, unsigned char* p_pbImage);
    typedef int (*T_ZAZRaw2BMP)(unsigned char* prawData, int w, int h, unsigned char* pbmpData);

    typedef void (*T_ZAZSetlog)(int val);
    typedef int (*T_ZAZAutoStore)(int* fingerid);
    typedef int (*T_ZAZGetFpList)(int imbnum, int* fplist);
    typedef int (*T_ZAZSetBaud)(HANDLE hHandle, int nAddr, int nBaudNum);
    typedef int (*T_ZAZSetSecurLevel)(HANDLE hHandle, int nAddr, int nLevel);
    typedef int (*T_ZAZSetPacketSize)(HANDLE hHandle, int nAddr, int nSize);
    typedef int (*T_ZAZUpChar2File)(HANDLE hHandle, int nAddr, int iBufferID, const char* pFileName);
    typedef int (*T_ZAZDownCharFromFile)(HANDLE hHandle, int nAddr, int iBufferID, const char* pFileName);
    typedef int (*T_ZAZSetChipAddr)(HANDLE hHandle, int nAddr, unsigned char* pChipAddr);
    typedef int (*T_ZAZBurnCode)(HANDLE hHandle, int nAddr, int nType, unsigned char* pImageData, int iLength);
    typedef int (*T_ZAZIdentify)(HANDLE hHandle, int nAddr, int* iMbAddress);
    typedef int (*T_ZAZEnroll)(HANDLE hHandle, int nAddr, int* nID);
    typedef void (*T_Delay)(int nTimes);

    typedef int (*T_FingerImgSorce)(unsigned char* pImage);
    typedef char* (*T_ZAZErr2Str)(int nErrCode);

    // libzamatch.so
    typedef short (*T_Match2Fp)(unsigned char* piFeatureA, unsigned char* piFeatureB);
    typedef short (*T_MatchScore)(unsigned char* piFeatureA, unsigned char* piFeatureB);
    typedef void (*T_AlgVersion)(char* postrVersion);
};

struct FPZADriverLib
{
    // libzaz.so
    T_ZAZ_MODE ZAZ_MODE;
    T_ZAZ_SETPATH ZAZ_SETPATH;
    T_ZAZ_Delaytime ZAZ_Delaytime;
    T_ZAZOpenDeviceEx ZAZOpenDeviceEx;
    T_ZAZCloseDeviceEx ZAZCloseDeviceEx;
    T_ZAZVfyPwd ZAZVfyPwd;
    T_ZAZGetImage ZAZGetImage;
    T_ZAZGenChar ZAZGenChar;
    T_ZAZMatch ZAZMatch;
    T_ZAZSearch ZAZSearch;

    T_ZAZRegModule ZAZRegModule;
    T_ZAZStoreChar ZAZStoreChar;
    T_ZAZDelChar ZAZDelChar;
    T_ZAZEmpty ZAZEmpty;
    T_ZAZReadParTable ZAZReadParTable;

    T_ZAZTemplateNum ZAZTemplateNum;
    T_ZAZGetRandomData ZAZGetRandomData;
    T_ZAZReadIndexTable ZAZReadIndexTable;
    T_ZAZDoUserDefine ZAZDoUserDefine;
    T_ZAZSetCharLen ZAZSetCharLen;
    T_ZAZSetImgLen ZAZSetImgLen;
    T_ZAZGetCharLen ZAZGetCharLen;
    T_ZAZLoadChar ZAZLoadChar;
    T_ZAZUpChar ZAZUpChar;
    T_ZAZDownChar ZAZDownChar;
    T_ZAZUpImage ZAZUpImage;
    T_ZAZDownImage ZAZDownImage;
    T_ZAZImgData2BMP ZAZImgData2BMP;
    T_ZAZGetImgDataFromBMP ZAZGetImgDataFromBMP;
    T_ZAZReadInfo ZAZReadInfo;
    T_ZAZWriteInfo ZAZWriteInfo;
    T_ZAZSetPwd ZAZSetPwd;
    T_ZAZReadInfPage ZAZReadInfPage;
    T_ZAZGetImgQuality ZAZGetImgQuality;
    T_ZAZRaw2BMP ZAZRaw2BMP;

    T_ZAZSetlog ZAZSetlog;
    T_ZAZAutoStore ZAZAutoStore;
    T_ZAZGetFpList ZAZGetFpList;
    T_ZAZSetBaud ZAZSetBaud;
    T_ZAZSetSecurLevel ZAZSetSecurLevel;
    T_ZAZSetPacketSize ZAZSetPacketSize;
    T_ZAZUpChar2File ZAZUpChar2File;
    T_ZAZDownCharFromFile ZAZDownCharFromFile;
    T_ZAZSetChipAddr ZAZSetChipAddr;
    T_ZAZBurnCode ZAZBurnCode;
    T_ZAZIdentify ZAZIdentify;
    T_ZAZEnroll ZAZEnroll;
    T_Delay Delay;

    T_FingerImgSorce FingerImgSorce;
    T_ZAZErr2Str ZAZErr2Str;

    // libzamatch.so
    T_Match2Fp Match2Fp;
    T_MatchScore MatchScore;
    T_AlgVersion AlgVersion;

    void loadSym(LIB_HANDLE libHandle, LIB_HANDLE m_libMatchHandle)
    {
        this->ZAZ_MODE = (T_ZAZ_MODE)dlsym(libHandle, "ZAZ_MODE");
        this->ZAZ_SETPATH = (T_ZAZ_SETPATH)dlsym(libHandle, "ZAZ_SETPATH");
        this->ZAZ_Delaytime = (T_ZAZ_Delaytime)dlsym(libHandle, "ZAZ_Delaytime");
        this->ZAZOpenDeviceEx = (T_ZAZOpenDeviceEx)dlsym(libHandle, "ZAZOpenDeviceEx");
        this->ZAZCloseDeviceEx = (T_ZAZCloseDeviceEx)dlsym(libHandle, "ZAZCloseDeviceEx");
        this->ZAZVfyPwd = (T_ZAZVfyPwd)dlsym(libHandle, "ZAZVfyPwd");
        this->ZAZGetImage = (T_ZAZGetImage)dlsym(libHandle, "ZAZGetImage");
        this->ZAZGenChar = (T_ZAZGenChar)dlsym(libHandle, "ZAZGenChar");
        this->ZAZMatch = (T_ZAZMatch)dlsym(libHandle, "ZAZMatch");
        this->ZAZSearch = (T_ZAZSearch)dlsym(libHandle, "ZAZSearch");
        this->ZAZRegModule = (T_ZAZRegModule)dlsym(libHandle, "ZAZRegModule");
        this->ZAZStoreChar = (T_ZAZStoreChar)dlsym(libHandle, "ZAZStoreChar");
        this->ZAZDelChar = (T_ZAZDelChar)dlsym(libHandle, "ZAZDelChar");
        this->ZAZEmpty = (T_ZAZEmpty)dlsym(libHandle, "ZAZEmpty");
        this->ZAZReadParTable = (T_ZAZReadParTable)dlsym(libHandle, "ZAZReadParTable");
        this->ZAZTemplateNum = (T_ZAZTemplateNum)dlsym(libHandle, "ZAZTemplateNum");
        this->ZAZGetRandomData = (T_ZAZGetRandomData)dlsym(libHandle, "ZAZGetRandomData");
        this->ZAZReadIndexTable = (T_ZAZReadIndexTable)dlsym(libHandle, "ZAZReadIndexTable");
        this->ZAZDoUserDefine = (T_ZAZDoUserDefine)dlsym(libHandle, "ZAZDoUserDefine");
        this->ZAZSetCharLen = (T_ZAZSetCharLen)dlsym(libHandle, "ZAZSetCharLen");
        this->ZAZSetImgLen = (T_ZAZSetImgLen)dlsym(libHandle, "ZAZSetImgLen");
        this->ZAZGetCharLen = (T_ZAZGetCharLen)dlsym(libHandle, "ZAZGetCharLen");
        this->ZAZLoadChar = (T_ZAZLoadChar)dlsym(libHandle, "ZAZLoadChar");
        this->ZAZUpChar = (T_ZAZUpChar)dlsym(libHandle, "ZAZUpChar");
        this->ZAZDownChar = (T_ZAZDownChar)dlsym(libHandle, "ZAZDownChar");
        this->ZAZUpImage = (T_ZAZUpImage)dlsym(libHandle, "ZAZUpImage");
        this->ZAZDownImage = (T_ZAZDownImage)dlsym(libHandle, "ZAZDownImage");
        this->ZAZImgData2BMP = (T_ZAZImgData2BMP)dlsym(libHandle, "ZAZImgData2BMP");
        this->ZAZGetImgDataFromBMP = (T_ZAZGetImgDataFromBMP)dlsym(libHandle, "ZAZGetImgDataFromBMP");
        this->ZAZReadInfo = (T_ZAZReadInfo)dlsym(libHandle, "ZAZReadInfo");
        this->ZAZWriteInfo = (T_ZAZWriteInfo)dlsym(libHandle, "ZAZWriteInfo");
        this->ZAZSetPwd = (T_ZAZSetPwd)dlsym(libHandle, "ZAZSetPwd");
        this->ZAZReadInfPage = (T_ZAZReadInfPage)dlsym(libHandle, "ZAZReadInfPage");
        this->ZAZGetImgQuality = (T_ZAZGetImgQuality)dlsym(libHandle, "ZAZGetImgQuality");
        this->ZAZRaw2BMP = (T_ZAZRaw2BMP)dlsym(libHandle, "ZAZRaw2BMP");
        this->ZAZSetlog = (T_ZAZSetlog)dlsym(libHandle, "ZAZSetlog");
        this->ZAZAutoStore = (T_ZAZAutoStore)dlsym(libHandle, "ZAZAutoStore");
        this->ZAZGetFpList = (T_ZAZGetFpList)dlsym(libHandle, "ZAZGetFpList");
        this->ZAZSetBaud = (T_ZAZSetBaud)dlsym(libHandle, "ZAZSetBaud");
        this->ZAZSetSecurLevel = (T_ZAZSetSecurLevel)dlsym(libHandle, "ZAZSetSecurLevel");
        this->ZAZSetPacketSize = (T_ZAZSetPacketSize)dlsym(libHandle, "ZAZSetPacketSize");
        this->ZAZUpChar2File = (T_ZAZUpChar2File)dlsym(libHandle, "ZAZUpChar2File");
        this->ZAZDownCharFromFile = (T_ZAZDownCharFromFile)dlsym(libHandle, "ZAZDownCharFromFile");
        this->ZAZSetChipAddr = (T_ZAZSetChipAddr)dlsym(libHandle, "ZAZSetChipAddr");
        this->ZAZBurnCode = (T_ZAZBurnCode)dlsym(libHandle, "ZAZBurnCode");
        this->ZAZIdentify = (T_ZAZIdentify)dlsym(libHandle, "ZAZIdentify");
        this->ZAZEnroll = (T_ZAZEnroll)dlsym(libHandle, "ZAZEnroll");
        this->Delay = (T_Delay)dlsym(libHandle, "Delay");
        this->FingerImgSorce = (T_FingerImgSorce)dlsym(libHandle, "FingerImgSorce");
        this->ZAZErr2Str = (T_ZAZErr2Str)dlsym(libHandle, "ZAZErr2Str");

        this->Match2Fp = (T_Match2Fp)dlsym(m_libMatchHandle, "Match2Fp");
        this->MatchScore = (T_MatchScore)dlsym(m_libMatchHandle, "MatchScore");
        this->AlgVersion = (T_AlgVersion)dlsym(m_libMatchHandle, "AlgVersion");

        this->isLoaded = true;
    };
    bool isLoaded = false;
};

REGISTER_DRIVER(FINGERPRINT_ZA_DRIVER_NAME, FPZADriver);

#define TEMPLATE_LEN 512

#define RETURN_IF_THERE_IS_ERROR_CODE(code, msg)                         \
    if (code != ZAZ_OK)                                                  \
    {                                                                    \
        KLOG_INFO() << msg << "error code: " << code << error2Str(code); \
        return code;                                                     \
    }

FPZADriver::FPZADriver(QObject* parent) : Driver(parent),
                                          m_libHandle(nullptr),
                                          m_libMatchHandle(nullptr)

{
    m_driverLib.reset(new FPZADriverLib);
    setName(FINGERPRINT_ZA_DRIVER_NAME);
}

FPZADriver::~FPZADriver()
{
    if (m_libHandle)
    {
        dlclose(m_libHandle);
        m_libHandle = NULL;
    }

    if (m_libMatchHandle)
    {
        dlclose(m_libMatchHandle);
        m_libMatchHandle = NULL;
    }
}

bool FPZADriver::initDriver(const QString& libPath)
{
    QString loadLibPath;
    libPath.isEmpty() ? (loadLibPath = FP_ZA_DRIVER_LIB) : (loadLibPath = libPath);
    return loadLibrary(FP_ZA_DRIVER_LIB);
}

bool FPZADriver::loadLibrary(const QString& libPath)
{
    // 打开指定的动态链接库文件；立刻决定返回前接触所有未决定的符号。若打开错误返回NULL，成功则返回库引用
    m_libHandle = dlopen(libPath.toStdString().c_str(), RTLD_NOW);
    if (m_libHandle == nullptr)
    {
        KLOG_ERROR() << "Load libzaz failed,error:" << dlerror();

        return false;
    }

    m_libMatchHandle = dlopen(FP_ZA_DRIVER_LIB_MATCH, RTLD_NOW);
    if (m_libMatchHandle == NULL)
    {
        KLOG_ERROR() << "Load libzamatch failed,error:" << dlerror();
        return false;
    }

    m_driverLib->loadSym(m_libHandle, m_libMatchHandle);
    return true;
}

bool FPZADriver::isLoaded()
{
    return m_driverLib->isLoaded;
}

/**
 * NOTE:
 * 注意，ZAZOpenDeviceEx 参数里的句柄，实际上是无效的，只是为了跟Windows兼容，真正的句柄在设备底层，因此，该参数传空
 */
int FPZADriver::openDevice()
{
    int nRet, iType = 0;
    HANDLE nhanle = 0;
    // 1.设置指纹协议
    m_driverLib->ZAZ_MODE(0);
    m_driverLib->ZAZSetlog(1);  // 开日志 日志在执行文件目录中  zazlog.txt

    // 2.设置指纹工作模式(PC||ARM)
    m_driverLib->ZAZ_SETPATH(fp_606, path_pc);
    nRet = m_driverLib->ZAZOpenDeviceEx(&nhanle, DEVICE_UDisk, 0, 2, 0);

    if (nRet != ZAZ_OK)
    {
        return nRet;
    }

    unsigned char pPassword[4] = {0, 0, 0, 0};
    nRet = m_driverLib->ZAZVfyPwd(nhanle, DEV_ADDR, pPassword);
    if (nRet == 0)
    {
        KLOG_INFO() << "open za device success: fp_606 ";
        iType = DEVICE_UDisk;
    }

    return nRet;
}

int FPZADriver::closeDevice()
{
    int ret = m_driverLib->ZAZCloseDeviceEx(0);
    return ret;
}

int FPZADriver::acquireFeature(int iBufferID, QByteArray& feature)
{
    int nRet = ZAZ_NO_FINGER;
    int counts = 0;

    HANDLE handle = 0;
    while (nRet == ZAZ_NO_FINGER)
    {
        nRet = m_driverLib->ZAZGetImage(handle, DEV_ADDR);
        counts++;
        KLOG_DEBUG() << "get fingerprint image:" << nRet << "count:" << counts;
    }
    RETURN_IF_THERE_IS_ERROR_CODE(nRet, "get fingerprint image fail");
    KLOG_DEBUG() << "get fingerprint image success";

    // 生成特征
    nRet = m_driverLib->ZAZGenChar(handle, DEV_ADDR, iBufferID);
    RETURN_IF_THERE_IS_ERROR_CODE(nRet, "gen feature fail");
    KLOG_DEBUG() << "gen feature success, buffer:" << iBufferID;

    // 从缓冲区拿出特征
    unsigned char pTemplet[2048];
    int iTempletLength = 0;
    m_driverLib->ZAZSetCharLen(TEMPLATE_LEN);

    nRet = m_driverLib->ZAZUpChar(handle, DEV_ADDR, iBufferID, pTemplet, &iTempletLength);
    RETURN_IF_THERE_IS_ERROR_CODE(nRet, "get feature  failed");
    KLOG_DEBUG() << "get feature success : " << iTempletLength;

    QByteArray bufferFeature((char*)pTemplet, TEMPLATE_LEN);
    feature = bufferFeature;

    return nRet;
}

QString FPZADriver::error2Str(int nErrCode)
{
    return QString(m_driverLib->ZAZErr2Str(nErrCode));
}

int FPZADriver::matchFeature(QByteArray& feature1, QByteArray& feature2)
{
    unsigned char charTableA[512];
    unsigned char charTableB[512];

    const char* byteArrayData = feature1.data();
    std::memcpy(charTableA, byteArrayData, feature1.size());

    const char* byteArrayData2 = feature2.data();
    std::memcpy(charTableB, byteArrayData2, feature2.size());

    int score = m_driverLib->MatchScore(charTableA, charTableB);
    KLOG_DEBUG() << "match score:" << score;

    return score;
}

int FPZADriver::templateMerge(QByteArray& mergedTemplate)
{
    int handle = 0;
    int ret;
    ret = m_driverLib->ZAZRegModule(handle, DEV_ADDR);
    RETURN_IF_THERE_IS_ERROR_CODE(ret, "template merge is Fail");

    unsigned char pTemplet[2048];
    int iTempletLength = 0;
    m_driverLib->ZAZSetCharLen(TEMPLATE_LEN);
    ret = m_driverLib->ZAZUpChar(handle, DEV_ADDR, 1, pTemplet, &iTempletLength);

    if (ret != ZAZ_OK)
    {
        KLOG_INFO() << "get template failed, error code: " << ret << error2Str(ret);
    }
    else
    {
        QByteArray templateByte((char*)pTemplet, TEMPLATE_LEN);
        KLOG_DEBUG() << "get template success, len:" << iTempletLength << " merged Template:" << templateByte;
        mergedTemplate = templateByte;
    }
    return ret;
}
}  // namespace Kiran
