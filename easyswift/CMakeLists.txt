project(easyswift)



add_executable(easyswift main.cpp)

target_link_libraries (easyswift Swiften boost_system boost_signals)