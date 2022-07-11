cmake_minimum_required(VERSION 3.8)

project(Set1_SingleByteXORCipher)

option(DEBUG_ENCODINGS "Enable debugging in encoding library" OFF)
option(DEBUG_CRYPTO "Enable debugging in crypto library" OFF)

if (DEBUG_ENCODINGS)
	add_definitions(-DDEBUG_ENC)
endif()

if (DEBUG_CRYPTO)
	add_definitions(-DDEBUG_CRYPT)
endif()

add_subdirectory(../../common build)

add_executable(decipher ${CMAKE_CURRENT_LIST_DIR}/src/main.c)

target_link_libraries(decipher encodings crypto)