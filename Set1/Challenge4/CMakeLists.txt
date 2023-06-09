cmake_minimum_required(VERSION 3.8)

project(Set1_DetectSingleByteXOR)

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

#add_subdirectory(../../common ${CMAKE_CURRENT_BINARY_DIR}/.objs/common)

add_executable(detect ${CMAKE_CURRENT_LIST_DIR}/src/main.c)

target_link_libraries(detect encodings crypto)

add_custom_command(
   TARGET detect POST_BUILD
   COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_LIST_DIR}/encripted.txt ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/resources
   COMMENT "Copying Challenge4 necessary files to output location..."
)