cmake_minimum_required(VERSION 3.2)

# init variables
if(SYSTEMD_FOUND)
  pkg_get_variable(SYSTEM_UNIT_DIR systemd systemdsystemunitdir)
else()
  set(SYSTEM_UNIT_DIR ${CMAKE_INSTALL_PREFIX}/lib/systemd/system)
endif()

# conf files
file(GLOB CONF_FILES ${PROJECT_SOURCE_DIR}/data/com*.conf)

foreach(CONF_FILE IN LISTS CONF_FILES)
  install(FILES ${CONF_FILE} DESTINATION ${SYSCONFDIR}/dbus-1/system.d)
endforeach()

configure_file(kiran-authentication-devices.service.in
                ${PROJECT_BINARY_DIR}/data/kiran-authentication-devices.service)

install(FILES ${PROJECT_BINARY_DIR}/data/kiran-authentication-devices.service
        DESTINATION ${SYSTEM_UNIT_DIR})


configure_file(com.kylinsec.Kiran.AuthDevice.service.in
                ${PROJECT_BINARY_DIR}/data/com.kylinsec.Kiran.AuthDevice.service)

install(FILES ${PROJECT_BINARY_DIR}/data/com.kylinsec.Kiran.AuthDevice.service
        DESTINATION ${CMAKE_INSTALL_FULL_DATADIR}/dbus-1/system-services)

install(FILES ${PROJECT_SOURCE_DIR}/data/driver.conf
        DESTINATION ${CONF_INSTALL_DIR})

install(FILES ${PROJECT_SOURCE_DIR}/data/device.conf
        DESTINATION ${CONF_INSTALL_DIR})

install(FILES ${PROJECT_SOURCE_DIR}/data/ukey-manager.conf
        DESTINATION ${CONF_INSTALL_DIR})

set(DRIVER_CONF_PATH ${CONF_INSTALL_DIR}/driver.conf)
set(DEVICE_CONF_PATH ${CONF_INSTALL_DIR}/device.conf)
set(UKEY_MANAGER_CONF_PATH ${CONF_INSTALL_DIR}/ukey-manager.conf)

configure_file(${CMAKE_SOURCE_DIR}/data/config.h.in ${CMAKE_BINARY_DIR}/config.h)