add_library(encodings SHARED 
	encodings.h
	encodings.c)

add_library(crypto SHARED
	crypto.h
	crypto.c)

target_include_directories(encodings PUBLIC 
	${CMAKE_CURRENT_LIST_DIR})

target_include_directories(crypto PUBLIC
	${CMAKE_CURRENT_LIST_DIR})