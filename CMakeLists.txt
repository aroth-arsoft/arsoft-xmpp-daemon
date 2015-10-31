cmake_minimum_required(VERSION 2.8)

project(arsoft-xmpp-daemon)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/")

option(BUILD_WITH_SYSTEMD "Use systemd" ON)

find_package(Boost REQUIRED COMPONENTS system signals program_options filesystem)
find_package(Swiften REQUIRED)
if(BUILD_WITH_SYSTEMD)
    find_package(SystemdDaemon)
endif()

set(ARSOFT_XMPP_DAEMON_MAJOR_VERSION 0)
set(ARSOFT_XMPP_DAEMON_MINOR_VERSION 8)
set(ARSOFT_XMPP_DAEMON_PATCH_VERSION 12)

configure_file(version.h.cmake "${CMAKE_CURRENT_BINARY_DIR}/arsoft-xmpp-daemon-version.h")
include_directories(${CMAKE_CURRENT_BINARY_DIR})

add_subdirectory(daemon/)

install(FILES
            config/daemon.conf
        DESTINATION ../etc/arsoft/xmpp-daemon)
