cmake_minimum_required(VERSION 3.8)

project(Set1_Hex2Base64)

option(DEBUG_ENCODINGS "Enable debugging in encoding library" OFF)

if (DEBUG_ENCODINGS)
	add_definitions(-DDEBUG_ENC)
endif()

add_executable(ch1_hex2base64 ${CMAKE_CURRENT_LIST_DIR}/src/main.c)

target_link_libraries(ch1_hex2base64 encodings)

add_custom_command(
   TARGET ch1_hex2base64 POST_BUILD
   COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_LIST_DIR}/The_String.txt ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/resources
   COMMENT "Copying Challenge 1 necessary files to output location..."
)