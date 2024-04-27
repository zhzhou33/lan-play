cmake_minimum_required (VERSION 3.15.0)
project (PCAP)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED true)
set(CMAKE_CXX_EXTENSIONS OFF)
set(WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})

set (SRC_LIST 
    main.cpp
    pcap_helper.cpp
    arp.cpp
    ether.cpp
    helper.cpp
)


add_executable(${CMAKE_PROJECT_NAME} ${SRC_LIST})
# Find the OpenSSL package

# Add the OpenSSL library to your target
target_link_libraries(${CMAKE_PROJECT_NAME} pcap)

# add_subdirectory(MyTinySTL)
target_include_directories(${CMAKE_PROJECT_NAME} PRIVATE
    include
)

# add_executable(hello ${TEST_SRC})
