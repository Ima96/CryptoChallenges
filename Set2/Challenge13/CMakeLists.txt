cmake_minimum_required(VERSION 3.8)

set(TARGET ch13_ecb_cut_n_paste)
set(TARGET_PRJ "Set2_${TARGET}")

project(${TARGET_PRJ})

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

add_executable(${TARGET} 
   ${CMAKE_CURRENT_LIST_DIR}/src/main.c
   ${CMAKE_CURRENT_LIST_DIR}/src/BasicUserProfile.c
   )

find_package(OpenSSL REQUIRED)
target_link_libraries(
   ${TARGET}
   OpenSSL::SSL 
   crypto
)
