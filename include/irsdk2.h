#ifndef __IRSDK2_H
#define __IRSDK2_H

#include "irsdk1.h"

#if WIN32
#	ifdef IRS_SDK2_DLL
#		define IRS_API_EXPORT     IRS_EXTERN_C WIN32_DLL_EXPORT
#	else
#		define IRS_API_EXPORT     IRS_EXTERN_C WIN32_DLL_IMPORT
#	endif
#elif ANDROID || LINUX || SYLIXOS
#	ifdef IRS_SDK2_DLL
#		define IRS_API_EXPORT     IRS_EXTERN_C LINUX_DLL_EXPORT
#	else
#		define IRS_API_EXPORT     IRS_EXTERN_C LINUX_DLL_IMPORT
#	endif
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef void *IRS_Handle;
typedef int IRS_Bool;

typedef enum _IRS_PARAM_TYPE {
	IRS_PARAM_NONE = 0x8000,

#  define _IRS_PARAM_ENTRY_ANY(a, ...) \
	IRS_PARAM_SET_##a, \
	IRS_PARAM_GET_##a,
/**/
#  define _IRS_PARAM_ENTRY(a, b, c) _IRS_PARAM_ENTRY_ANY(a, b, c)
#  define _IRS_PARAM_ARRAY_ENTRY(a, b, c, d) _IRS_PARAM_ENTRY_ANY(a, b, c, d)
#  define _IRS_PARAM_ENTRY_DEV_RW_OLD_STYLE(a, b, c) _IRS_PARAM_ENTRY_ANY(a, b, c)
#  define _IRS_PARAM_ENTRY_DEVCTL(a, ...) _IRS_PARAM_ENTRY_ANY(a)

#  define __concat1(x,y) x##y
#  define __concat(x,y)  __concat1(x,y)
#  define _HARD_CODE_ENUM_VALUE(v)  __concat(__enum_value_,__LINE__) = IRS_PARAM_NONE + v,

#include "irs_param_defs.h"

#  undef _IRS_PARAM_ENTRY_ANY
#  undef _IRS_PARAM_ENTRY
#  undef _IRS_PARAM_ARRAY_ENTRY
#  undef _IRS_PARAM_ENTRY_DEV_RW_OLD_STYLE
#  undef _IRS_PARAM_ENTRY_DEVCTL
#  undef _IRS_PARAM_ENTRY_AT

	IRS_PARAM_SELECT_DEVICE   = 0x9000,

} IRS_PARAM_TYPE;

typedef enum _IRS_CONTROL_TYPE {
	IRS_CONTROL_NONE = 0x1000,

	IRS_CONTROL_SET_IMAGE_CALLBACK,
	IRS_CONTROL_SET_RESULT_CALLBACK,
	IRS_CONTROL_SET_SYNC_MODE,
	IRS_CONTROL_GET_MISC_MSG,
	IRS_CONTROL_GET_RESULT,
	IRS_CONTROL_GET_IRIS_PREVIEW_IMAGE,
	IRS_CONTROL_GET_FACE_PREVIEW_IMAGE,

	IRS_CONTROL_GET_WORK_MODE = 0x1057,
	IRS_CONTROL_CANCEL_OPR = 0x1058,
	IRS_CONTROL_START_ENROLL = 0x1061,
	IRS_CONTROL_START_RECO,
	IRS_CONTROL_START_DETECT,
	IRS_CONTROL_START_ACQUIRE,
	IRS_CONTROL_START_LIVENESS_CHECK,
	IRS_CONTROL_START_ENFORCE,
	IRS_CONTROL_START_ID_VERIFY,

	IRS_CONTROL_OPEN_REAL_DEVICE = 0x10C0,
	IRS_CONTROL_SET_POWER_STATE,
	IRS_CONTROL_GET_POWER_STATE,

	IRS_CONTROL_IRIS_LIGHT,

	IRS_CONTROL_CREATE_ENCRYPTED_IMAGE,
	IRS_CONTROL_FREE_ENCRYPTED_IMAGE,

	IRS_CONTROL_MOTOR_RESET_REGULAR,
	IRS_CONTROL_MOTOR_RESET_CALIBRATED,

	IRS_CONTROL_SET_ID_FACE_IMAGE,
	IRS_CONTROL_FLUSH_ZLOG,
	IRS_CONTROL_SET_PARAMS_FROM_STRINGS,
	IRS_CONTROL_SAVE_BURST_IMAGES,
	IRS_CONTROL_GET_DEVICE_BUS_TYPE,

	IRS_CONTROL_CHECK_IRIS_IS_EXIST,
	IRS_CONTROL_CAPTURE_NIR_FACE_IMAGE,
	IRS_CONTROL_GET_CURRENT_DEVICE_MODE,
	IRS_CONTROL_FACE_LOG_PACKING,

	IRS_CONTROL_GET_WORK_RESULTS,
	IRS_CONTROL_RELEASE_WORK_RESULTS,
	IRS_CONTROL_GET_MISC_MESSAGE,
	IRS_CONTROL_GET_PREVIEW_IMAGE,
	IRS_CONTROL_RELEASE_PREVIEW_IMAGE,

	IRS_CONTROL_XDEVICE_CONTROL = 0x1200,
	IRS_CONTROL_SET_XDEVICE_CONTROL_FUNCTION,

	IRS_CONTROL_GET_PARAMTER_ID = 0x2800,
	IRS_CONTROL_GET_SUPPORTED_PARAMTER_LIST,

} IRS_CONTROL_TYPE;

typedef enum _IRS_MSG_TYPE {
	IRS_MSG_WORK_RESULT = 0x3000,
	IRS_MSG_DISTANCE,
	IRS_MSG_TEMPERATURE,
} IRS_MSG_TYPE;

typedef struct _IRS_FeatureArray {
	int sizeInBytes;
	int numFeatures;   /*注册图像*/
	int featureSize;   /*单个特征的长度*/
	void *featureData; /*特征数据*/
} IRS_FeatureArray;

typedef struct _IRS_FeatureArrayV2 {
	int sizeInBytes;
	int numFeatures;        /*特征数量*/
	int featureSize;        /*单个特征的长度*/
	union {
		void *featureArray;
		void *featureData;
		void *leftFeatureData;  /*左眼特征数据*/
	};
	void *rightFeatureData; /*右眼特征数据*/

	int vid;
	IRS_Bool copy;
	int featureType;  // 0 - Iris v1, 1 - Iris v2, 2 - Face, 3 - Palm
} IRS_FeatureArrayV2;

typedef struct _IRS_FeatureArrayV2 IRS_IrisFeatureArray;

typedef struct _IRS_ImageEncryptionData {
	int imageFormat;
	IRS_Image imageIn;
	IRS_Image imageOut;
} IRS_ImageEncryptionData;

typedef struct _IRS_XdevControlData {
	int code;
	void *data;
	int len;
} IRS_XdevControlData;

typedef struct _IRS_ParameterDescription {
	int value;
	const char *name;
} IRS_ParameterDescription;

typedef struct _IRS_CheckIrisExistData {
	int matchedIndex;		//比中索引
	int matchedScore;		//比对分数
	int numFeatures;		//比对特征数量
	void *featureData;		//比对特征，左右左右存放特征
	IRS_Image leftEyeImg;	//左眼图像
	IRS_Image rightEyeImg; 	//右眼图像
} IRS_CheckIrisExistData;

typedef struct _IRS_DeviceInfo {
	IRS_Handle handle;
	char deviceType[48];
	char serialNumber[48];
	char sensorType[48];
} IRS_DeviceInfo;

typedef void (*IRS_IMAGE_CALLBACK_FUNCTION)(IRS_Image *);
typedef void (*IRS_RESULTS_CALLBACK_FUNCTION)(IRS_Results *);

enum IRS_DEVICE_MODE {
	IRS_DEVICE_MODE_IDLE,		//	Idle state. Device is not open.
	IRS_DEVICE_MODE_RUNNING,	//	Running state. The device is opened and is working.
	IRS_DEVICE_MODE_STALL,		//	Device stall state. Some devices are malfunctioning at this moment. Not unloaded.
	IRS_DEVICE_MODE_RECOVER,	//	Recover state. The device is in recover mode.
	IRS_DEVICE_MODE_UNLOAD,		//	Device unloaded. When the opened devices number != current attached devices.
};

typedef struct _IRS_FaceLogPacking {
	const char *srcName;
	const char *dstName;
} IRS_FaceLogPacking;

#ifdef __cplusplus
}
#endif

//===========================================================================================================================//
#if !defined(IRS_SDK2_DLL) && !defined(__ZLOG_V2_H)

#ifndef IRS_LOG_TAG
# define IRS_LOG_TAG NULL
#endif

#define __ZLOG_TAG(level, tag, fmt, ...) \
	IRS_logPrint(IRS_LOG_##level, tag, __FILE__, __func__, __LINE__, fmt "\n", ##__VA_ARGS__)

#define ZLOGVV_TAG(tag, fmt, ...) \
	__ZLOG_TAG(VERBOSE2, tag, fmt, ##__VA_ARGS__)

#define ZLOGV_TAG(tag, fmt, ...) \
	__ZLOG_TAG(VERBOSE, tag, fmt, ##__VA_ARGS__)

#define ZLOGD_TAG(tag, fmt, ...) \
	__ZLOG_TAG(DEBUG, tag, fmt, ##__VA_ARGS__)

#define ZLOGI_TAG(tag, fmt, ...) \
	__ZLOG_TAG(INFO, tag, fmt, ##__VA_ARGS__)

#define ZLOGW_TAG(tag, fmt, ...) \
	__ZLOG_TAG(WARNING, tag, fmt, ##__VA_ARGS__)

#define ZLOGE_TAG(tag, fmt, ...) \
	__ZLOG_TAG(ERROR, tag, fmt, ##__VA_ARGS__)

#define __ZLOG_TAG_IF(condition, level, tag, fmt, ...) do{ \
	if(condition) \
		__ZLOG_TAG(level, tag, fmt, ##__VA_ARGS__); \
} while(0)

#define ZLOGVV_TAG_IF(condition, tag, fmt, ...) \
	__ZLOG_TAG_IF(condition, VERBOSE2, tag, fmt "\n", ##__VA_ARGS__)

#define ZLOGV_TAG_IF(condition, tag, fmt, ...) \
	__ZLOG_TAG_IF(condition, VERBOSE, tag, fmt "\n", ##__VA_ARGS__)

#define ZLOGD_TAG_IF(condition, tag, fmt, ...) \
	__ZLOG_TAG_IF(condition, DEBUG, tag, fmt "\n", ##__VA_ARGS__)

#define ZLOGI_TAG_IF(condition, tag, fmt, ...) \
	__ZLOG_TAG_IF(condition, INFO, tag, fmt "\n", ##__VA_ARGS__)

#define ZLOGW_TAG_IF(condition, tag, fmt, ...) \
	__ZLOG_TAG_IF(condition, WARNING, tag, fmt "\n", ##__VA_ARGS__)

#define ZLOGE_TAG_IF(condition, tag, fmt, ...) \
	__ZLOG_TAG_IF(condition, ERROR, tag, fmt "\n", ##__VA_ARGS__)

# define ZLOGVV(fmt, ...) \
	ZLOGVV_TAG(IRS_LOG_TAG, fmt "\n", ##__VA_ARGS__)
# define ZLOGVV_IF(condition, fmt, ...) \
	ZLOGVV_TAG_IF(condition, IRS_LOG_TAG, fmt "\n", ##__VA_ARGS__)
# define ZLOGV(fmt, ...) \
	ZLOGV_TAG(IRS_LOG_TAG, fmt "\n", ##__VA_ARGS__)
# define ZLOGV_IF(condition, fmt, ...) \
	ZLOGV_TAG_IF(condition, IRS_LOG_TAG, fmt "\n", ##__VA_ARGS__)
# define ZLOGD(fmt, ...) \
	ZLOGD_TAG(IRS_LOG_TAG, fmt "\n", ##__VA_ARGS__)
# define ZLOGD_IF(condition, fmt, ...) \
	ZLOGD_TAG_IF(condition, IRS_LOG_TAG, fmt "\n", ##__VA_ARGS__)
# define ZLOGI(fmt, ...) \
	ZLOGI_TAG(IRS_LOG_TAG, fmt "\n", ##__VA_ARGS__)
# define ZLOGI_IF(condition, fmt, ...) \
	ZLOGI_TAG_IF(condition, IRS_LOG_TAG, fmt "\n", ##__VA_ARGS__)
# define ZLOGW(fmt, ...) \
	ZLOGW_TAG(IRS_LOG_TAG, fmt "\n", ##__VA_ARGS__)
# define ZLOGW_IF(condition, fmt, ...) \
	ZLOGW_TAG_IF(condition, IRS_LOG_TAG, fmt "\n", ##__VA_ARGS__)
# define ZLOGE(fmt, ...) \
	ZLOGE_TAG(IRS_LOG_TAG, fmt "\n", ##__VA_ARGS__)

#define ZLOG        ZLOGD
#define ZLOG_IF     ZLOGD_IF
#define ZLOG_TAG    ZLOGD_TAG
#define ZLOG_TAG_IF ZLOGD_TAG_IF

#endif
//===========================================================================================================================//

#define DEVICE_HANDLE_OFFSET   817

#endif


