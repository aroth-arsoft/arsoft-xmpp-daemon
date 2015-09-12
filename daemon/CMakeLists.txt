add_definitions(-DBOOST_SIGNALS_NO_DEPRECATION_WARNING)

if(BUILD_WITH_SYSTEMD)
    add_definitions(-DWITH_SYSTEMD=1)
    include_directories(${SYSTEMDDAEMON_INCLUDE_DIR})
endif()

include_directories(${SWIFTEN_INCLUDE_DIR})
include_directories(${Boost_INCLUDE_DIRS})

add_executable(arsoft-xmpp-daemon
    main.cpp
    xmpp_agent.cpp
    xmpp_agent.h
    daemon_config.cpp
    daemon_config.h
    server.cpp
    server.h
    xhtml_payload.h
    xhtml_payload.cpp
    )

target_link_libraries (arsoft-xmpp-daemon ${SWIFTEN_LIBRARY} ${Boost_LIBRARIES} pthread)
install(TARGETS arsoft-xmpp-daemon RUNTIME DESTINATION bin)

if(BUILD_WITH_SYSTEMD)
    target_link_libraries (arsoft-xmpp-daemon ${SYSTEMDDAEMON_LIBRARIES})
endif()
