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

add_executable(ch4_detect ${CMAKE_CURRENT_LIST_DIR}/src/main.c)

target_link_libraries(ch4_detect encodings cryptopals)

add_custom_command(
   TARGET ch4_detect POST_BUILD
   COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_LIST_DIR}/encripted.txt ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/resources/ciphertext4.txt
   COMMENT "Copying Challenge 4 necessary files to output location..."
)