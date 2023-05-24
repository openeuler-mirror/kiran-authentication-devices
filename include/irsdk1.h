#ifndef IRSDKV1_H
#define IRSDKV1_H

#ifdef __cplusplus
#	define IRS_EXTERN_C extern "C"
#	define IRS_EXTERN_C_BEGIN extern "C" {
#	define IRS_EXTERN_C_END   }
#else
#	define IRS_EXTERN_C
#	if !defined(false) && !defined(true) && !defined(bool)
  		enum _BoolValueEnums { false, true } ;
		typedef _Bool bool;
#	endif
#	define IRS_EXTERN_C
#	define IRS_EXTERN_C_BEGIN
#	define IRS_EXTERN_C_END
#endif

#ifndef FALSE
#	define FALSE 0
#endif
#ifndef TRUE
#	define TRUE 1
#endif

#if __GNUC__ || __clang__
#	define IRS_NORETURN __attribute__((noreturn))
#elif _MSC_VER
#	define IRS_NORETURN __declspec(noreturn)
#else
#   error Unknown compiler!
#endif

#define IRS_CASE(x)   case x : {
#define IRS_ESAC(...) break; }

IRS_EXTERN_C_BEGIN

typedef long long IRS_TimeStamp;
typedef unsigned int IRS_HwTimeStamp;

#define IRS_BIO_TYPE_NONE        0
#define IRS_BIO_TYPE_LEFT_IRIS   1
#define IRS_BIO_TYPE_RIGHT_IRIS  2
#define IRS_BIO_TYPE_IRIS        (IRS_BIO_TYPE_LEFT_IRIS|IRS_BIO_TYPE_RIGHT_IRIS)
#define IRS_BIO_TYPE_FACE        4
#define IRS_BIO_TYPE_RGB_FACE    4
#define IRS_BIO_TYPE_NIR_FACE    8
#define IRS_BIO_TYPE_PALM        16
#define IRS_BIO_TYPE_ANY_IRIS    0x80

#define IRS_WORK_MODE_IDLE           0
#define IRS_WORK_MODE_ENRL           1
#define IRS_WORK_MODE_RECO           2
#define	IRS_WORK_MODE_DETECT         3
#define	IRS_WORK_MODE_ACQUIRE        4
#define	IRS_WORK_MODE_LIVENESS_CHECK 5
#define	IRS_WORK_MODE_ENFORCE        6
#define	IRS_WORK_MODE_ID_VERIFY      7
#define IRS_WORK_MODE_MAX_           8

#define ___cpube32(x) \
	(((x) >> 24) | ((x) << 24) |\
	((((x) >> 8) & 0xFF00)) | ((((x) << 8) & 0xFF0000)))

#define _cpube32(x) ___cpube32((unsigned int)x)

#define IRS_IMAGE_TYPE_RAW   _cpube32(0x52415700)
#define IRS_IMAGE_TYPE_BMP   _cpube32(0x424d5000)
#define IRS_IMAGE_TYPE_JPG   _cpube32(0x4a504700)
//#define IRS_IMAGE_TYPE_FILE  _cpube32(0x46494c45)
#define IRS_IMAGE_FROM_FILE  0x80000000

#define IRS_BIO_FEAT_COLOR_CONTACT     0x0001
#define IRS_BIO_FEAT_GLASS             0x0002
#define IRS_BIO_FEAT_NIR_FACE_LIVENESS 0x0004
#define IRS_BIO_FEAT_IRIS_LIVENESS     0x0008
#define IRS_BIO_FEAT_RGB_FACE_LIVENESS 0x0010
#define IRS_BIO_FEAT_FACEMASK          0x0100

#define IRS_TS_VALUE_INVAL 3
#define IRS_TS_VALUE_FALSE 0
#define IRS_TS_VALUE_TRUE  1

typedef union _IRS_BioFeatures {
	struct {
		int rgbFaceLiveness : 2;
		int nirFaceLiveness : 2;
		int irisLiveness    : 2;
		int coloredLens     : 2;
		int glass           : 2;
		int faceMask        : 2;
	};
	int asInt;
} IRS_BioFeatures;

typedef struct _IRS_VersionInfo {
	/* hw versions */
	char hw_hVersion[128];
	char hw_bVersion[128];
	char hw_fVersion[128];
	char hw_lVersion[128];
	/* base iris implementation library version */
	union {
		char algoIrisLibVersion[128];
		struct {
			char first127[127];
			char isReleaseVersion;
		};
	};
	/* algo versions */
	char algoDetectVersion[128];
	char algoEyeVersion[128];
	char algoIrisVersion[128];
	char algoTofVersion[128];
	char algoMotorControlVersion[128];
	char algoAttributeVersion[128];
	char algoImgProcVersion[128];
	char algoFaceVersion[128];
	/* sdk versions */
	char algo2Version[128];
	char coreVersion[128];
	char irsdkVersion[128];
	char lazyboxVersion[128];
	char deviceDriverVersion[128];
} IRS_VersionInfo;

typedef struct _IRS_VersionInfoV2 {
	char *pos;
	/* hw versions */
	char *hw_hVersion;
	char *hw_bVersion;
	char *hw_fVersion;
	char *hw_lVersion;
	/* base iris implementation library version */
	char *algoIrisLibVersion;
	/* algo versions */
	char *algoDetectVersion;
	char *algoEyeVersion;
	char *algoIrisVersion;
	char *algoTofVersion;
	char *algoMotorControlVersion;
	char *algoAttributeVersion;
	char *algoImgProcVersion;
	char *algoFaceVersion;
	/* sdk versions */
	char *algo2Version;
	char *coreVersion;
	char *irsdkVersion;
	char *lazyboxVersion;
	char *deviceDriverVersion;
	char privBuffer[128 * 18];
} IRS_VersionInfoV2;

typedef struct _IRS_ParamInitEntry {
	int paraId;
	void *data;
	int dataLen;
} IRS_ParamInitEntry;

typedef struct _IRS_Image {
	int sizeInBytes;
	int bioType;
	int imgType;       /*类型：raw, bmp, jpg, ...*/
	const void *data;  /*图像数据*/
	union {
		int width;     /*宽度；使用于raw类型*/
		int dataLen;   /*图像数据长度；适用于bmp，jpg类型*/
	};
	int height;        /*高度*/
	int bytesPerPixel; /*每像素字节数*/

	union {
		struct {
			IRS_HwTimeStamp hwTimeStamp;
			int qualityScore;
		};
		unsigned short rect[4];
	};
	const char *desc; /* private0 -> desc, 2022/6/2 */

	/* 不要修改以下数据!! */
	void *privateData1;
	void *privateData2;
	void *privateData3;
	void *privateData4;
	void *privateData5;
	void *privateData6;
	void *privateData7;
} IRS_Image;

#define INIT_IRS_IMAGE(img) { memset(img, 0, sizeof(IRS_Image)); (img)->sizeInBytes = sizeof(IRS_Image); }

typedef struct _IRS_EnrollData {
	int sizeInBytes;
	IRS_Image image;          /*注册图像*/
	IRS_Image encryptedImage; /*加密的注册图像*/
	const void *featureData;  /*注册特征*/
	int featureDataLen;       /*注册特征长度*/
} IRS_EnrollData;

typedef struct _IRS_Results {
	int sizeInBytes;
	int msg2;
	int failureCode;

	unsigned int elapsedTime;
	int workMode;
	int bioType;
	IRS_TimeStamp startTime;

	union {
		struct {
			double matchedScore;
			int matchedIndex;
			unsigned int opId;
			bool eos;
			int deviceId;
			int matchFailureCount;
		};

		bool boolValue;
		int intValue;
		double doubleValue;

		int currentDistance; /*当前的距离*/
		double currentTemperature;/*当前温度*/
		int currentMotorAngle;
		struct {
			int x, y, width, height;
		} irisEyePos[2];
		char string1[1];

		struct {
			int numImageList;
			int *selectedImageIndices;
			IRS_Image *imageList;
		};
	};

	union {
		struct {
			IRS_BioFeatures leftEyeBioFlags;   /*左眼生物特征：美瞳，眼镜，...*/
			IRS_BioFeatures rightEyeBioFlags;  /*右眼生物特征：美瞳，眼镜，...*/
		};
		IRS_BioFeatures faceBioFlags;    /*人脸生物特征*/
		IRS_BioFeatures irisBioFlags[2];
	};
	union {
		struct {
			IRS_EnrollData leftEyeData, rightEyeData;
		};
		struct {
			IRS_EnrollData faceData, faceData2;
		};
		IRS_EnrollData palmData;
		struct {
			int _intArray9[9];
			IRS_Image _imageArray9[9];
		};
	};

	void *privateData0;
	void *privateData1;
	void *privateData2;
	void *privateData3;
	void *privateData4;
	void *privateData5;
	void *privateData6;
	void *privateData7;

} IRS_Results;

#define INIT_IRS_RESULTS(results) { \
	memset(results, 0, sizeof(IRS_Results)); \
	(results)->sizeInBytes = sizeof(IRS_Results); \
	(results)->leftEyeBioFlags.asInt = -1; \
	(results)->rightEyeBioFlags.asInt = -1; \
	(results)->faceBioFlags.asInt = -1; \
}

typedef enum _IRS_MSG2_TYPE {
	IRS_MSG2_NONE,

	IRS_MSG2_LEFT_IRIS_ENROLLED = 0x100,
	IRS_MSG2_RIGHT_IRIS_ENROLLED,
	IRS_MSG2_DOUBLE_IRISES_ENROLLED,
	IRS_MSG2_FACE_ENROLLED,
	IRS_MSG2_PALM_ENROLLED,

	IRS_MSG2_LEFT_IRIS_RECOGNIZED = 0x200,
	IRS_MSG2_RIGHT_IRIS_RECOGNIZED,
	IRS_MSG2_FACE_RECOGNIZED,
	IRS_MSG2_PALM_RECOGNIZED,

	IRS_MSG2_FACE_DETECTED = 0x300,

	IRS_MSG2_IRIS_LIVENESS_CHECKED = 0x308,
	IRS_MSG2_NIR_FACE_LIVENESS_CHECKED,
	IRS_MSG2_RGB_FACE_LIVENESS_CHECKED,

	IRS_MSG2_LEFT_IRIS_ACQUIRED = 0x400,
	IRS_MSG2_RIGHT_IRIS_ACQUIRED,
	IRS_MSG2_DOUBLE_IRISES_ACQUIRED,
	IRS_MSG2_FACE_ACQUIRED,
	IRS_MSG2_PALM_ACQUIRED,

	IRS_MSG2_IRIS_ENROLLING_FAILED = 0x500,
	IRS_MSG2_LEFT_IRIS_ENROLLING_FAILED,
	IRS_MSG2_RIGHT_IRIS_ENROLLING_FAILED,
	IRS_MSG2_FACE_ENROLLING_FAILED,
	IRS_MSG2_IRIS_RECOGNIZING_FAILED,
	IRS_MSG2_FACE_RECOGNIZING_FAILED,
	IRS_MSG2_FACE_DETECTING_FAILED,
	IRS_MSG2_IRIS_ACQUIRING_FAILED,
	IRS_MSG2_LEFT_IRIS_ACQUIRING_FAILED,
	IRS_MSG2_RIGHT_IRIS_ACQUIRING_FAILED,
	IRS_MSG2_FACE_ACQUIRING_FAILED,
	IRS_MSG2_IRIS_LIVENESS_CHECKING_FAILED,
	IRS_MSG2_NIR_FACE_LIVENESS_CHECKING_FAILED,
	IRS_MSG2_RGB_FACE_LIVENESS_CHECKING_FAILED,
	IRS_MSG2_PALM_ENROLLING_FAILED,
	IRS_MSG2_PALM_RECOGNIZING_FAILED,

	IRS_MSG2_DISTANCE_UPDATED = 0x600,
	IRS_MSG2_TEMPERATURE_UPDATED,
	IRS_MSG2_VCM_SET,
	IRS_MSG2_MOTOR_ANGLE_SET,
	IRS_MSG2_IRIS_EYE_POS,
	IRS_MSG2_LOG_FILE_COMPLETED,
	IRS_MSG2_REBOOT_DEVICE,
	IRS_MSG2_FACE_MASK_DETECTED,
	IRS_MSG2_OPTIONAL_IRIS_IMAGE,
	IRS_MSG2_INTERACTIVE_IRIS_ENROLLING,
	IRS_MSG2_SET_RGB_LIGHT,

} IRS_MSG2_TYPE;

enum IRS_LogLevel {
	IRS_LOG_ERROR,
	IRS_LOG_WARNING,
	IRS_LOG_INFO,

	IRS_LOG_DEBUG,
	IRS_LOG_VERBOSE,
	IRS_LOG_VERBOSE2,
	IRS_LOG_VERBOSE3,

	IRS_LOG_NULL,
};

#if __GNUC__ || __clang__
#	define IRS_FMT_LLD "%lld"
#elif _MSC_VER
#	define IRS_FMT_LLD "%I64d"
#endif

IRS_EXTERN_C_END

/*--------------------- ERROR CODE ---------------------*/
#define IRS2_ERROR_EYE_POS           -8001
#define IRS2_ERROR_INVALID_LENGTH    -8002
#define IRS2_ERROR_LOW_SCORE         -8003
#define IRS2_ERROR_INVALID_SIGNATURE -8004
#define IRS2_ERROR_DEVICE_FAILURE    -8005
#define IRS2_ERROR_TIMEDOUT          -8006
#define IRS2_ERROR_OUT_OF_RANGE      -8007
#define IRS2_ERROR_BUFFER_TOO_SHORT  -8008
#define IRS2_ERROR_NOT_PROCESSED     -8009
#define IRS2_ERROR_INVALID_DATA      -8010
#define IRS2_ERROR_PENDING           -8011
#define IRS2_ERROR_UNINITIALIZED     -8012
#define IRS2_ERROR_NOT_EXIST         -8013
#define IRS2_ERROR_EMPTY_BUFFER      -8014
#define IRS2_ERROR_NULL_POINTER      -8015
#define IRS2_ERROR_INVALID_ARGUMENT  -8016
#define IRS2_ERROR_CANCELLED         -8017
#define IRS2_ERROR_ALREADY_EXISTED   -8018
#define IRS2_ERROR_INVALID_STATE     -8019
#define IRS2_ERROR_INVALID_VERSION   -8020
#define IRS2_ERROR_OUT_OF_MEMORY     -8021
#define IRS2_ERROR_NOT_FOUND         -8022
#define IRS2_ERROR_INVALID_NAME      -8023
#define IRS2_ERROR_FACE_MASKED       -8024
#define IRS2_ERROR_INVALID_FORMAT    -8025
#define IRS2_ERROR_INVALID_SEQNUM    -8026
#define IRS2_ERROR_NOT_READY         -8027
#define IRS2_ERROR_NEGATIVE_RESULT   -8028
#define IRS2_ERROR_BUFFER_OVERFLOW   -8029
#define IRS2_ERROR_BUFFER_UNDERFLOW  IRS2_ERROR_BUFFER_TOO_SHORT
#define IRS2_ERROR_END_OF_STREAM     -8030

#define IRS2_ERROR_OPENCV_EXCEPTION  -8080
#define IRS2_ERROR_ALGO_EXCEPTION    -8088
#define IRS2_ERROR_BUSY              -8099
/*--------------------- ERROR CODE ---------------------*/

#define WIN32_DLL_EXPORT __declspec(dllexport)
#define WIN32_DLL_IMPORT __declspec(dllimport)
#define LINUX_DLL_EXPORT __attribute__((visibility("default")))
#define LINUX_DLL_IMPORT

#endif


