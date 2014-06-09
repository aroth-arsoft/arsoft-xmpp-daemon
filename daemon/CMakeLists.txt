add_definitions(-DBOOST_SIGNALS_NO_DEPRECATION_WARNING)

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

