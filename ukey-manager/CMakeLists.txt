set(TARGET_NAME kiran-ukey-manager)

file(GLOB_RECURSE UKEY_MANAGER_SRC "./*.cpp" "./*.h")

file(GLOB_RECURSE UKEY_DRIVER_SRC ${PROJECT_SOURCE_DIR}/src/driver/ukey/*.cpp 
                                  ${PROJECT_SOURCE_DIR}/src/driver/ukey/*.h )

set(DEVICE_SDK ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}/${PROJECT_NAME}-sdk)

set(CMAKE_BUILD_WITH_INSTALL_RPATH TRUE)
set(CMAKE_INSTALL_RPATH ${DEVICE_SDK}/ukey/ft)

set(TS_FILES "${CMAKE_CURRENT_SOURCE_DIR}/translations/${TARGET_NAME}.zh_CN.ts")

qt5_create_translation(QM_FILES 
                      ${CMAKE_CURRENT_SOURCE_DIR} 
                      ${TS_FILES}
                      )

add_executable(${TARGET_NAME}
        ${UKEY_MANAGER_SRC}
        ${UKEY_DRIVER_SRC}
        ${QM_FILES}
        )

target_include_directories(${TARGET_NAME} PRIVATE
        ${PROJECT_SOURCE_DIR}/src/driver/ukey
        ${PROJECT_SOURCE_DIR}/include
        ${KLOG_QT5_INCLUDE_DIRS}
        ${PROJECT_BINARY_DIR}
        )

target_link_libraries(${TARGET_NAME}
        Qt5::Core
        ${KLOG_QT5_LIBRARIES}
        ${CMAKE_DL_LIBS})  


install(TARGETS ${TARGET_NAME} 
    DESTINATION ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_BINDIR})    

install(FILES ${QM_FILES} DESTINATION ${TRANSLATION_INSTALL_DIR})