cmake_minimum_required(VERSION 3.8)

project(Set1_RepeatingKeyXOR)

option(DEBUG_ENCODINGS "Enable debugging in encoding library" OFF)
option(DEBUG_CRYPTO "Enable debugging in crypto library" OFF)

if (DEBUG_ENCODINGS)
	add_definitions(-DDEBUG_ENC)
endif()

if (DEBUG_CRYPTO)
	add_definitions(-DDEBUG_CRYPT)
endif()

string(TOLOWER ${CMAKE_BUILD_TYPE} build_type)
if (build_type STREQUAL debug)
  add_definitions(-DDEBUG_APP)
endif()

add_subdirectory(../../common ${CMAKE_CURRENT_BINARY_DIR}/.objs/common)

add_executable(encript-rkxor ${CMAKE_CURRENT_LIST_DIR}/src/main.c)

target_link_libraries(encript-rkxor encodings crypto)