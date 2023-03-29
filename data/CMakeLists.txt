cmake_minimum_required(VERSION 3.2)

set(SYSCONFDIR "/etc")
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

install(FILES ${PROJECT_SOURCE_DIR}/data/drivers.conf
        DESTINATION ${SYSCONFDIR}/${PROJECT_NAME})

install(FILES ${PROJECT_SOURCE_DIR}/data/third-party-devices.conf
        DESTINATION ${SYSCONFDIR}/${PROJECT_NAME})

set(KAD_INSTALL_INCLUDE ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_INCLUDEDIR}/${PROJECT_NAME})

install(FILES ${PROJECT_SOURCE_DIR}/include/kiran-auth-device-i.h
        DESTINATION ${KAD_INSTALL_INCLUDE}/)