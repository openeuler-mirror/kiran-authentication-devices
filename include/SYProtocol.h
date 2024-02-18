#ifndef  _SYPROTOCOL_H_
#define  _SYPROTOCOL_H_
 
#define HANDLE int


//////////////////////////////////////
#define ZAZ_OK                0x00    // 执行成功
#define ZAZ_COMM_ERR          0x01    // 数据包接收错误
#define ZAZ_NO_FINGER         0x02    // 传感器上没有手指
#define ZAZ_GET_IMG_ERR       0x03    // 录入指纹图象失败
#define ZAZ_FP_TOO_DRY        0x04    // 指纹太淡
#define ZAZ_FP_TOO_WET        0x05    // 指纹太糊
#define ZAZ_FP_DISORDER       0x06    // 指纹太乱
#define ZAZ_LITTLE_FEATURE    0x07    // 指纹特征点太少
#define ZAZ_NOT_MATCH         0x08    // 指纹不匹配
#define ZAZ_NOT_SEARCHED      0x09    // 没搜索到指纹
#define ZAZ_MERGE_ERR         0x0a    // 特征合并失败
#define ZAZ_ADDRESS_OVER      0x0b    // 地址号超出指纹库范围
#define ZAZ_READ_ERR          0x0c    // 从指纹库读模板出错
#define ZAZ_UP_TEMP_ERR       0x0d    // 上传特征失败
#define ZAZ_RECV_ERR          0x0e    // 模块不能接收后续数据包
#define ZAZ_UP_IMG_ERR        0x0f    // 上传图象失败
#define ZAZ_DEL_TEMP_ERR      0x10    // 删除模板失败
#define ZAZ_CLEAR_TEMP_ERR    0x11    // 清空指纹库失败
#define ZAZ_SLEEP_ERR         0x12    // 不能进入休眠
#define ZAZ_INVALID_PASSWORD  0x13    // 口令不正确
#define ZAZ_RESET_ERR         0x14    // 系统复位失败
#define ZAZ_INVALID_IMAGE     0x15    // 无效指纹图象
#define ZAZ_HANGOVER_UNREMOVE 0X17    


/////////////////////////////////////////////
#define CHAR_BUFFER_A          0x01
#define CHAR_BUFFER_B          0x02
#define MODEL_BUFFER           0x03

/////////////////
#define COM1                   0x01
#define COM2                   0x02
#define COM3                   0x03

/////////////////////////////////////////
#define BAUD_RATE_9600         0x00
#define BAUD_RATE_19200        0x01
#define BAUD_RATE_38400        0x02
#define BAUD_RATE_57600        0x03   //default
#define BAUD_RATE_115200       0x04

 
typedef unsigned char BYTE;

/////////////////////////////////////////
 
//参数fptype
#define fp_602 1 
#define fp_606 2  
#define fp_608 3
#define fp_xbt 4 
#define fp_fl  5
#define fp_kvm 6


//参数path
#define path_proc 0 //表示usb路径：/proc/bus/usb
#define path_dev  1 //表示usb路径：/dev/bus/usb

#define path_pc   1  
#define path_arm  0 


#define FP_ZA_DRIVER_LIB "libzaz.so"
#define FP_ZA_DRIVER_LIB_MATCH "libzamatch.so"
#define FP_ZA_MEGER_TEMPLATE_COUNT 2

#define DEVICE_USB		0
#define DEVICE_COM		1
#define DEVICE_UDisk	2

#define IMAGE_X 256
#define IMAGE_Y 360

#define DEV_ADDR 0xffffffff
#endif

