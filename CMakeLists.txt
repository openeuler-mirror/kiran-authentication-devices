
cmake_minimum_required(VERSION 3.2)

project(kiran-authentication-devices)

include(GNUInstallDirs)

find_package(PkgConfig REQUIRED)
find_package(Qt5 REQUIRED COMPONENTS Core DBus Sql Concurrent LinguistTools)
pkg_search_module(KLOG_QT5 REQUIRED klog-qt5)

set(CMAKE_INCLUDE_CURRENT_DIR ON)

set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(TRANSLATION_INSTALL_DIR ${CMAKE_INSTALL_FULL_DATADIR}/${PROJECT_NAME}/translations)
configure_file(${CMAKE_SOURCE_DIR}/data/config.h.in ${CMAKE_BINARY_DIR}/config.h)

add_subdirectory(src)
add_subdirectory(data)
add_subdirectory(ukey-manager)

