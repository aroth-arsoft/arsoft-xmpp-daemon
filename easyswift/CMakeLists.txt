cmake_minimum_required(VERSION 2.8)

project(easyswift)


add_definitions(-DBOOST_SIGNALS_NO_DEPRECATION_WARNING)

add_executable(easyswift
    main.cpp
    xmpp_agent.cpp
    xmpp_agent.h
    daemon_config.cpp
    daemon_config.h
    server.cpp
    server.h
    )

target_link_libraries (easyswift Swiften boost_system boost_signals boost_program_options boost_filesystem pthread)