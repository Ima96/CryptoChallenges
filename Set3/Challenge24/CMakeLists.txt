cmake_minimum_required(VERSION 3.20)

set(TARGET ch24_MT19937_stream_cipher)
set(TARGET_PRJ "Set3_${TARGET}")

project(${TARGET_PRJ})

option(DEBUG_ENCODINGS "Enable debugging in encoding library" OFF)
option(DEBUG_CRYPTO "Enable debugging in crypto library" OFF)

string(TOLOWER ${CMAKE_BUILD_TYPE} build_type)
if (build_type STREQUAL debug)
   if (DEBUG_APP)
      add_definitions(-DDEBUG_MAIN)
      message(STATUS "${TARGET_PRJ}: Debugging application")
   endif()
endif()

add_executable(${TARGET} 
   ${CMAKE_CURRENT_LIST_DIR}/src/main.c
   )

find_package(OpenSSL REQUIRED)
target_link_libraries(
   ${TARGET}
   OpenSSL::SSL 
   cryptopals
   misc
)
