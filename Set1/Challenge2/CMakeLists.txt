cmake_minimum_required(VERSION 3.8)

project(Set1_FixedXOR)

option(DEBUG_ENCODINGS "Enable debugging in encoding library" OFF)

if (DEBUG_ENCODINGS)
	add_definitions(-DDEBUG_ENC)
endif()

if (DEBUG_CRYPTO)
	add_definitions(-DDEBUG_CRYPT)
endif()

add_executable(ch2_XOR ${CMAKE_CURRENT_LIST_DIR}/src/main.c)
target_link_libraries(ch2_XOR encodings cryptopals)