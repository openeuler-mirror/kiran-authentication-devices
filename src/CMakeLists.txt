pkg_search_module(LIBUDEV REQUIRED libudev)

file(GLOB_RECURSE SRC_H_FILES ./*.h)
file(GLOB_RECURSE SRC_CPP_FILES ./*.cpp)

ADD_DEFINITIONS(-DQT_NO_KEYWORDS)

qt5_add_dbus_adaptor(
  AUTH_DEVICE_MANAGER_ADAPTOR_SRCS
  ${CMAKE_SOURCE_DIR}/data/com.kylinsec.Kiran.AuthDevice.xml
  ${CMAKE_SOURCE_DIR}/src/auth-device-manager.h
  Kiran::AuthDeviceManager
  auth_device_manager_adaptor
  AuthDeviceManagerAdaptor)

  qt5_add_dbus_adaptor(
  AUTH_DEVICE_ADAPTOR_SRCS
  ${CMAKE_SOURCE_DIR}/data/com.kylinsec.Kiran.AuthDevice.Device.xml
  ${CMAKE_SOURCE_DIR}/src/device/auth-device.h
  Kiran::AuthDevice
  auth_device_adaptor
  AuthDeviceAdaptor)

set(DEVICE_SDK ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}/${PROJECT_NAME}-sdk)

set(CMAKE_BUILD_WITH_INSTALL_RPATH TRUE)
set(CMAKE_INSTALL_RPATH ${DEVICE_SDK}/finger-vein/sd:${DEVICE_SDK}/fingerprint/zk:${DEVICE_SDK}/ukey/skf:${DEVICE_SDK}/multi-function/iristar
                        :${DEVICE_SDK}/fingerprint/zhiang)


set(TS_FILES "${PROJECT_SOURCE_DIR}/translations/${PROJECT_NAME}.zh_CN.ts")
qt5_create_translation(QM_FILES 
                      ${CMAKE_CURRENT_SOURCE_DIR} 
                      ${TS_FILES}
                      )

add_executable(${PROJECT_NAME} 
                ${SRC_H_FILES}
                ${SRC_CPP_FILES}
                ${AUTH_DEVICE_MANAGER_ADAPTOR_SRCS}
                ${AUTH_DEVICE_ADAPTOR_SRCS}
                ${QM_FILES}
                )


target_include_directories(${PROJECT_NAME} PUBLIC
                            ${KLOG_QT5_INCLUDE_DIRS}
                            ${PROJECT_BINARY_DIR}
                            ${PROJECT_SOURCE_DIR}/src
                            ${PROJECT_SOURCE_DIR}/include
                            )
                            
target_link_libraries(${PROJECT_NAME}
                        ${KLOG_QT5_LIBRARIES}
                        ${LIBUDEV_LIBRARIES}
                        Qt5::Core
                        Qt5::DBus
                        Qt5::Sql
                        Qt5::Concurrent
                        ${CMAKE_DL_LIBS}
                        )

target_link_directories(${PROJECT_NAME} PRIVATE
                      )

install(TARGETS ${PROJECT_NAME} 
    DESTINATION ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_BINDIR})    

install(FILES ${QM_FILES} DESTINATION ${TRANSLATION_INSTALL_DIR})
