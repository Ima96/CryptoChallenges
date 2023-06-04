add_library(encodings SHARED 
	encodings.h
	encodings.c)

add_library(crypto SHARED
	crypto.h
	crypto.c)

add_library(misc SHARED
	misc.h
   misc.c)

find_package(OpenSSL REQUIRED)
target_link_libraries(
	crypto
	OpenSSL::SSL
)

target_include_directories(encodings PUBLIC 
	${CMAKE_CURRENT_LIST_DIR})

target_include_directories(crypto PUBLIC
	${CMAKE_CURRENT_LIST_DIR})

target_include_directories(misc PUBLIC
	${CMAKE_CURRENT_LIST_DIR})