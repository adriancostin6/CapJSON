cmake_minimum_required(VERSION 3.1)

project(cap-json LANGUAGES CXX)

set (CMAKE_CXX_STANDARD 14)
set (CMAKE_CXX_STANDARD_REQUIRED True)
set (CMAKE_BUILD_TYPE Release)

add_executable(${PROJECT_NAME}
    src/capture.h
    src/capture.cpp
    src/main.cpp
    src/network_packet.h
    src/network_packet.cpp
    src/json.h
    src/json.cpp
    src/utility.h
    src/utility.cpp
)

set(RAPIDJSON_INCLUDE_DIR ${CMAKE_SOURCE_DIR}/external/rapidjson/include)

if(WIN32)
	#find libtins library on windows
	#requires that both the libtins library and the WinPCAP developer pack are stored in the external directory

	set (LIBTINS_INCLUDE_DIR ${CMAKE_SOURCE_DIR}/external/libtins/include)
	set (WINPCAP_DEV_PACK ${CMAKE_SOURCE_DIR}/external/WpdPack/Include)

    find_library(LIBTINS tins 
            ${CMAKE_SOURCE_DIR}/external/libtins/build/lib/Release
            )

    find_library(WPCAP wpcap 
            ${CMAKE_SOURCE_DIR}/external/WpdPack/Lib/x64
            )

    find_library(PACKET Packet 
            ${CMAKE_SOURCE_DIR}/external/WpdPack/Lib/x64
            )

    include_directories(
            ${LIBTINS_INCLUDE_DIR} 
            ${WINPCAP_DEV_PACK} 
            ${RAPIDJSON_INCLUDE_DIR}
            )

    target_link_libraries(${PROJECT_NAME} 
            ${LIBTINS} ${WPCAP} ${PACKET} ws2_32 Iphlpapi
            )

	add_compile_definitions(TINS_STATIC)

else()
	#find the libtins library on Linux and other UNIX like operating systems

	find_package(libtins REQUIRED)

    include_directories(${RAPIDJSON_INCLUDE_DIR})

	target_link_libraries(${CMAKE_PROJECT_NAME} tins -pthread)
endif()
