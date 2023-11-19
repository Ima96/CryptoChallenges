cmake_minimum_required(VERSION 3.20)

project(
   CryptoPalsChallenges
   LANGUAGES C CXX
)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wno-pointer-sign -Wstack-protector")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wstack-protector")

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/lib)
set(BUILD_OBJECTS_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/.obj)

option(DEBUG_ENCODINGS  "Enable debugging in encoding library."   OFF)
option(DEBUG_CRYPTO     "Enable debugging in crypto library."     OFF)
option(BUILD_TESTS      "Enable building tests of challenges."    OFF)
option(DEBUG_APP        "Enable debugging the main app"           OFF)

if (DEBUG_ENCODINGS)
	add_definitions(-DDEBUG_ENC)
endif()

if (DEBUG_CRYPTO)
	add_definitions(-DDEBUG_CRYPT)
endif()

if ("${CMAKE_BUILD_TYPE}" STREQUAL "")
   message(STATUS "Setting CMAKE_BUILD_TYPE to default Debug")
   set(CMAKE_BUILD_TYPE "Debug" CACHE INTERNAL "Default build type")
endif()

string(TOLOWER ${CMAKE_BUILD_TYPE} build_type)
if (build_type STREQUAL debug)
   if (DEBUG_APP)
      add_definitions(-DDEBUG_MAIN)
   endif()
endif()

message(STATUS "Building for: ${CMAKE_BUILD_TYPE}")

file(MAKE_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/resources)

add_subdirectory(common ${BUILD_OBJECTS_DIRECTORY}/common)

add_subdirectory(Set1 ${BUILD_OBJECTS_DIRECTORY}/Set1)

add_subdirectory(Set2 ${BUILD_OBJECTS_DIRECTORY}/Set2)

add_subdirectory(Set3 ${BUILD_OBJECTS_DIRECTORY}/Set3)

if (BUILD_TESTS)
   add_subdirectory(tests ${BUILD_OBJECTS_DIRECTORY}/tests)
endif()