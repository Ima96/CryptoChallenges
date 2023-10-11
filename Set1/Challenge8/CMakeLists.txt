cmake_minimum_required(VERSION 3.8)

project(Set1_DetectAES-ECB)

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

add_executable(ch8_detect_aes-ecb ${CMAKE_CURRENT_LIST_DIR}/src/main.c)

find_package(OpenSSL REQUIRED)
target_link_libraries(
   ch8_detect_aes-ecb
   OpenSSL::SSL 
   encodings
   crypto
   misc
)

add_custom_command(
   TARGET ch8_detect_aes-ecb POST_BUILD
   COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_LIST_DIR}/ciphertext8.txt ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/resources
   COMMENT "Copying Challenge 8 necessary files to output location..."
)