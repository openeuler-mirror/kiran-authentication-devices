set(CMAKE_INCLUDE_CURRENT_DIR ON)

set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(PkgConfig REQUIRED)
find_package(Qt5 REQUIRED COMPONENTS Core DBus Sql Concurrent LinguistTools)

pkg_search_module(KLOG_QT5 REQUIRED klog-qt5)
pkg_search_module(LIBUDEV REQUIRED libudev)

file(GLOB_RECURSE SRC_H_FILES ./*.h)
file(GLOB_RECURSE SRC_CPP_FILES ./*.cpp)

ADD_DEFINITIONS(-DQT_NO_KEYWORDS)

qt_add_dbus_adaptor(
  AUTH_DEVICE_MANAGER_ADAPTOR_SRCS
  ${CMAKE_SOURCE_DIR}/data/com.kylinsec.Kiran.AuthDevice.xml
  ${CMAKE_SOURCE_DIR}/src/auth-device-manager.h
  Kiran::AuthDeviceManager
  auth_device_manager_adaptor
  AuthDeviceManagerAdaptor)

  qt_add_dbus_adaptor(
  AUTH_DEVICE_ADAPTOR_SRCS
  ${CMAKE_SOURCE_DIR}/data/com.kylinsec.Kiran.AuthDevice.Device.xml
  ${CMAKE_SOURCE_DIR}/src/device/auth-device.h
  Kiran::AuthDevice
  auth_device_adaptor
  AuthDeviceAdaptor)

set(DEVICE_SDK ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}/${PROJECT_NAME}-sdk)

set(CMAKE_BUILD_WITH_INSTALL_RPATH TRUE)
set(CMAKE_INSTALL_RPATH ${DEVICE_SDK}/finger-vein/sd:${DEVICE_SDK}/fingerprint/zk:${DEVICE_SDK}/ukey/ft)


set(TS_FILES "${PROJECT_SOURCE_DIR}/translations/${PROJECT_NAME}.zh_CN.ts")
qt_create_translation(QM_FILES 
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

include_directories(${PROJECT_SOURCE_DIR}/include
                    )

target_include_directories(${PROJECT_NAME} PUBLIC
                            ${KLOG_QT5_INCLUDE_DIRS}
                            ${CMAKE_CURRENT_SOURCE_DIR}
                            )

target_link_libraries(${PROJECT_NAME}
                        ${KLOG_QT5_LIBRARIES}
                        ${LIBUDEV_LIBRARIES}
                        Qt5::Core
                        Qt5::DBus
                        Qt5::Sql
                        Qt5::Concurrent
                        )

target_link_directories(${PROJECT_NAME} PRIVATE
                      )

install(TARGETS ${PROJECT_NAME} 
    DESTINATION ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_BINDIR})    


set(TRANSLATION_INSTALL_DIR ${CMAKE_INSTALL_FULL_DATADIR}/${PROJECT_NAME}/translations)
configure_file(config.h.in ${CMAKE_CURRENT_BINARY_DIR}/config.h)
install(FILES ${QM_FILES} DESTINATION ${TRANSLATION_INSTALL_DIR})