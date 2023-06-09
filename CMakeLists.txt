cmake_minimum_required(VERSION 3.20)

project(
   CryptoPalsChallenges
   LANGUAGES C CXX
)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/lib)
set(BUILD_OBJECTS_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/.obj)

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

add_subdirectory(common ${BUILD_OBJECTS_DIRECTORY}/common)

add_subdirectory(Set1 ${BUILD_OBJECTS_DIRECTORY}/Set1)

add_subdirectory(Set2 ${BUILD_OBJECTS_DIRECTORY}/Set2)

