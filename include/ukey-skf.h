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

#pragma once
#include <stdint.h>
#include <QString>
#include <QObject>

#ifdef __cplusplus
extern "C"
{
#endif

typedef int8_t INT8;
typedef int16_t INT16;
typedef int32_t INT32;
typedef unsigned char UINT8;
typedef uint16_t UINT16;
typedef uint32_t UINT32;
typedef long BOOL;

typedef UINT8 BYTE;
typedef UINT8 CHAR;
typedef INT16 SHORT;
typedef UINT16 USHORT;
typedef INT32 LONG;
typedef UINT32 ULONG;
typedef UINT32 UINT;
typedef UINT16 WORD;
typedef UINT32 DWORD;
typedef UINT32 FLAGS;
typedef CHAR *LPSTR;
typedef void *HANDLE;
typedef HANDLE DEVHANDLE;
typedef HANDLE HAPPLICATION;
typedef HANDLE HCONTAINER;

#define MAX_RSA_MODULUS_LEN 256
#define MAX_RSA_EXPONENT_LEN 4
#define ECC_MAX_XCOORDINATE_BITS_LEN 512
#define ECC_MAX_YCOORDINATE_BITS_LEN 512
#define ECC_MAX_MODULUS_BITS_LEN 512

#define MAX_IV_LEN 32
#define MAX_FILE_NAME_SIZE 32
#define MAX_FILE_CONTAINER_NAME_SIZE 64

/*Permission type*/
#define SECURE_NEVER_ACCOUNT 0x00000000
#define SECURE_ADM_ACCOUNT 0x00000001
#define SECURE_USER_ACCOUNT 0x00000010
#define SECURE_ANYONE_ACCOUNT 0x000000FF

#ifndef FALSE
#define FALSE 0x00000000
#endif

#ifndef TRUE
#define TRUE 0x00000001
#endif

#ifndef ADMIN_TYPE
#define ADMIN_TYPE 0
#endif

#ifndef USER_TYPE
#define USER_TYPE 1
#endif

/* public key usage */
#define SGD_PK_SIGN 0x0100
#define SGD_PK_DH 0x0200
#define SGD_PK_ENC 0x0400

/* public key types */
#define SGD_RSA 0x00010000
#define SGD_RSA_SIGN (SGD_RSA | SGD_PK_SIGN)
#define SGD_RSA_ENC (SGD_RSA | SGD_PK_ENC)
#define SGD_SM2 0x00020000
#define SGD_SM2_1 (SGD_SM2 | SGD_PK_SIGN)
#define SGD_SM2_2 (SGD_SM2 | SGD_PK_DH)
#define SGD_SM2_3 (SGD_SM2 | SGD_PK_ENC)

/* hash */
#define SGD_SM3			0x00000001
#define SGD_SHA1		0x00000002
#define SGD_SHA256		0x00000004
#define SGD_HASH_FROM		0x00000008
#define SGD_HASH_TO		0x000000FF

/* signatue schemes */
#define SGD_SM3_RSA		(SGD_SM3|SGD_RSA)
#define SGD_SHA1_RSA		(SGD_SHA1|SGD_RSA)
#define SGD_SHA256_RSA		(SGD_SHA256|SGD_RSA)
#define SGD_SM3_SM2		(SGD_SM3|SGD_SM2)
#define SGD_SIG_FROM		0x00040000
#define SGD_SIG_TO		0x800000FF

#pragma pack(1)
    typedef struct Struct_Version
    {
        BYTE major;
        BYTE minor;
    } VERSION;

    typedef struct Struct_DEVINFO
    {
        VERSION Version;
        CHAR Manufacturer[64];
        CHAR Issuer[64];
        CHAR Label[32];
        CHAR SerialNumber[32];
        VERSION HWVersion;
        VERSION FirmwareVersion;
        ULONG AlgSymCap;
        ULONG AlgAsymCap;
        ULONG AlgHashCap;
        ULONG DevAuthAlgId;
        ULONG TotalSpace;
        ULONG FreeSpace;
        ULONG MaxECCBufferSize;
        ULONG MaxBufferSize;
        BYTE Reserved[64];
    } DEVINFO, *PDEVINFO;

    typedef struct Struct_RSAPUBLICKEYBLOB
    {
        ULONG AlgID;
        ULONG BitLen;
        BYTE Modulus[MAX_RSA_MODULUS_LEN];
        BYTE PublicExponent[MAX_RSA_EXPONENT_LEN];
    } RSAPUBLICKEYBLOB, *PRSAPUBLICKEYBLOB;

    typedef struct Struct_RSAPRIVATEKEYBLOB
    {
        ULONG AlgID;
        ULONG BitLen;
        BYTE Modulus[MAX_RSA_MODULUS_LEN];
        BYTE PublicExponent[MAX_RSA_EXPONENT_LEN];
        BYTE PrivateExponent[MAX_RSA_MODULUS_LEN];
        BYTE Prime1[MAX_RSA_MODULUS_LEN / 2];
        BYTE Prime2[MAX_RSA_MODULUS_LEN / 2];
        BYTE Prime1Exponent[MAX_RSA_MODULUS_LEN / 2];
        BYTE Prime2Exponent[MAX_RSA_MODULUS_LEN / 2];
        BYTE Coefficient[MAX_RSA_MODULUS_LEN / 2];
    } RSAPRIVATEKEYBLOB, *PRSAPRIVATEKEYBLOB;

    typedef struct Struct_ECCPUBLICKEYBLOB
    {
        ULONG BitLen;
        BYTE XCoordinate[ECC_MAX_XCOORDINATE_BITS_LEN / 8];
        BYTE YCoordinate[ECC_MAX_YCOORDINATE_BITS_LEN / 8];
    } ECCPUBLICKEYBLOB, *PECCPUBLICKEYBLOB;

    typedef struct Struct_ECCPRIVATEKEYBLOB
    {
        ULONG BitLen;
        BYTE PrivateKey[ECC_MAX_MODULUS_BITS_LEN / 8];
    } ECCPRIVATEKEYBLOB, *PECCPRIVATEKEYBLOB;

    typedef struct Struct_ECCCIPHERBLOB
    {
        BYTE XCoordinate[ECC_MAX_XCOORDINATE_BITS_LEN / 8];
        BYTE YCoordinate[ECC_MAX_XCOORDINATE_BITS_LEN / 8];
        BYTE HASH[32];
        ULONG CipherLen;
        BYTE Cipher[1];
    } ECCCIPHERBLOB, *PECCCIPHERBLOB;

    typedef struct Struct_ECCSIGNATUREBLOB
    {
        BYTE r[ECC_MAX_XCOORDINATE_BITS_LEN / 8];
        BYTE s[ECC_MAX_XCOORDINATE_BITS_LEN / 8];
    } ECCSIGNATUREBLOB, *PECCSIGNATUREBLOB;

    typedef struct Struct_BLOCKCIPHERPARAM
    {
        BYTE IV[MAX_IV_LEN];
        ULONG IVLen;
        ULONG PaddingType;
        ULONG FeedBitLen;
    } BLOCKCIPHERPARAM, *PBLOCKCIPHERPARAM;

    typedef struct SKF_ENVELOPEDKEYBLOB
    {
        ULONG Version;
        ULONG ulSymmAlgID;
        ULONG ulBits;
        BYTE cbEncryptedPriKey[64];
        ECCPUBLICKEYBLOB PubKey;
        ECCCIPHERBLOB ECCCipherBlob;
    } ENVELOPEDKEYBLOB, *PENVELOPEDKEYBLOB;

    typedef struct Struct_FILEATTRIBUTE
    {
        CHAR FileName[MAX_FILE_NAME_SIZE];
        ULONG FileSize;
        ULONG ReadRights;
        ULONG WriteRights;
    } FILEATTRIBUTE, *PFILEATTRIBUTE;
#pragma pack()

#define SAR_OK 0x00000000
#define SAR_FAIL 0x0A000001
#define SAR_UNKNOWNERR 0x0A000002
#define SAR_NOTSUPPORTYETERR 0x0A000003
#define SAR_FILEERR 0x0A000004
#define SAR_INVALIDHANDLEERR 0x0A000005
#define SAR_INVALIDPARAMERR 0x0A000006
#define SAR_READFILEERR 0x0A000007
#define SAR_WRITEFILEERR 0x0A000008
#define SAR_NAMELENERR 0x0A000009
#define SAR_KEYUSAGEERR 0x0A00000A
#define SAR_MODULUSLENERR 0x0A00000B
#define SAR_NOTINITIALIZEERR 0x0A00000C
#define SAR_OBJERR 0x0A00000D
#define SAR_MEMORYERR 0x0A00000E
#define SAR_TIMEOUTERR 0x0A00000F
#define SAR_INDATALENERR 0x0A000010
#define SAR_INDATAERR 0x0A000011
#define SAR_GENRANDERR 0x0A000012
#define SAR_HASHOBJERR 0x0A000013
#define SAR_HASHERR 0x0A000014
#define SAR_GENRSAKEYERR 0x0A000015
#define SAR_RSAMODULUSLENERR 0x0A000016
#define SAR_CSPIMPRTPUBKEYERR 0x0A000017
#define SAR_RSAENCERR 0x0A000018
#define SAR_RSADECERR 0x0A000019
#define SAR_HASHNOTEQUALERR 0x0A00001A
#define SAR_KEYNOTFOUNTERR 0x0A00001B
#define SAR_CERTNOTFOUNTERR 0x0A00001C
#define SAR_NOTEXPORTERR 0x0A00001D
#define SAR_DECRYPTPADERR 0x0A00001E
#define SAR_MACLENERR 0x0A00001F
#define SAR_BUFFER_TOO_SMALL 0x0A000020
#define SAR_KEYINFOTYPEERR 0x0A000021
#define SAR_NOT_EVENTERR 0x0A000022
#define SAR_DEVICE_REMOVED 0x0A000023
#define SAR_PIN_INCORRECT 0x0A000024
#define SAR_PIN_LOCKED 0x0A000025
#define SAR_PIN_INVALID 0x0A000026
#define SAR_PIN_LEN_RANGE 0x0A000027
#define SAR_USER_ALREADY_LOGGED_IN 0x0A000028
#define SAR_USER_PIN_NOT_INITIALIZED 0x0A000029
#define SAR_USER_TYPE_INVALID 0x0A00002A
#define SAR_APPLICATION_NAME_INVALID 0x0A00002B
#define SAR_APPLICATION_EXISTS 0x0A00002C
#define SAR_USER_NOT_LOGGED_IN 0x0A00002D
#define SAR_APPLICATION_NOT_EXISTS 0x0A00002E
#define SAR_FILE_ALREADY_EXIST 0x0A00002F
#define SAR_NO_ROOM 0x0A000030
#define SAR_FILE_NOT_EXIST 0x0A000031
#define SAR_REACH_MAX_CONTAINER_COUNT 0x0A000032

typedef struct {
	ULONG err;
	QString reason;
} SKF_ERR_REASON;

static SKF_ERR_REASON skf_errors[] = {
	{ SAR_OK,			"success" },
	{ SAR_FAIL,			"failure" },
	{ SAR_UNKNOWNERR,		"unknown error" },
	{ SAR_NOTSUPPORTYETERR,		"operation not supported" },
	{ SAR_FILEERR,			"file error" },
	{ SAR_INVALIDHANDLEERR,		"invalid handle" },
	{ SAR_INVALIDPARAMERR,		"invalid parameter" },
	{ SAR_READFILEERR,		"read file failure" },
	{ SAR_WRITEFILEERR,		"write file failure" },
	{ SAR_NAMELENERR,		"invalid name length" },
	{ SAR_KEYUSAGEERR,		"invalid key usage" },
	{ SAR_MODULUSLENERR,		"invalid modulus length" },
	{ SAR_NOTINITIALIZEERR,		"not initialized" },
	{ SAR_OBJERR,			"invalid object" },
	{ SAR_MEMORYERR,		"memory error" },
	{ SAR_TIMEOUTERR,		"timeout" },
	{ SAR_INDATALENERR,		"invalid input length" },
	{ SAR_INDATAERR,		"invalid input value" },
	{ SAR_GENRANDERR,		"random generation failed" },
	{ SAR_HASHOBJERR,		"invalid digest handle" },
	{ SAR_HASHERR,			"digest error" },
	{ SAR_GENRSAKEYERR,		"rsa key generation failure" },
	{ SAR_RSAMODULUSLENERR,		"invalid rsa modulus length" },
	{ SAR_CSPIMPRTPUBKEYERR,	"csp import public key error" },
	{ SAR_RSAENCERR,		"rsa encryption failure" },
	{ SAR_RSADECERR,		"rsa decryption failure" },
	{ SAR_HASHNOTEQUALERR,		"hash not equal" },
	{ SAR_KEYNOTFOUNTERR,		"key not found" },
	{ SAR_CERTNOTFOUNTERR,		 "certificate not found" },
	{ SAR_NOTEXPORTERR,		"export failed" },
	{ SAR_DECRYPTPADERR,		"decrypt invalid padding" },
	{ SAR_MACLENERR,		"invalid mac length" },
	{ SAR_BUFFER_TOO_SMALL,		"buffer too small" },
	{ SAR_KEYINFOTYPEERR,		"invalid key info type" },
	{ SAR_NOT_EVENTERR,		"no event" },
	{ SAR_DEVICE_REMOVED,		"device removed" },
	{ SAR_PIN_INCORRECT,		"pin incorrect" },
	{ SAR_PIN_LOCKED,		 "pin locked" },
	{ SAR_PIN_INVALID,		"invalid pin" },
	{ SAR_PIN_LEN_RANGE,		"invalid pin length" },
	{ SAR_USER_ALREADY_LOGGED_IN,	"user already logged in" },
	{ SAR_USER_PIN_NOT_INITIALIZED,	"user pin not initialized" },
	{ SAR_USER_TYPE_INVALID,	 "invalid user type" },
	{ SAR_APPLICATION_NAME_INVALID, "invalid application name" },
	{ SAR_APPLICATION_EXISTS,	"application already exist" },
	{ SAR_USER_NOT_LOGGED_IN,	"user not logged in" },
	{ SAR_APPLICATION_NOT_EXISTS,	"application not exist" },
	{ SAR_FILE_ALREADY_EXIST,	"file already exist" },
	{ SAR_NO_ROOM,			"no space" },
	{ SAR_FILE_NOT_EXIST,		"file not exist" },
};

#ifdef __cplusplus
}
#endif
