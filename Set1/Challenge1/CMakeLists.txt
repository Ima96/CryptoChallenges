cmake_minimum_required(VERSION 3.8)

project(Set1_Hex2Base64)

option(DEBUG_ENCODINGS "Enable debugging in encoding library" OFF)

if (DEBUG_ENCODINGS)
	add_definitions(-DDEBUG_ENC)
endif()

add_subdirectory(../../common build)

add_executable(hex2base64 ${CMAKE_CURRENT_LIST_DIR}/src/main.c)

target_link_libraries(hex2base64 encodings)