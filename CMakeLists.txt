cmake_minimum_required(VERSION 2.8)

project(arsoft-xmpp-daemon)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/")

find_package(Boost REQUIRED COMPONENTS system signals program_options filesystem)
find_package(Swiften REQUIRED)

add_subdirectory(daemon/)

install(FILES
            upstart/arsoft-xmpp-daemon-setup.conf
            upstart/arsoft-xmpp-daemon.conf
        DESTINATION ../etc/init)
