add_library(encodings SHARED 
	encodings.h
	encodings.c)

add_library(cryptopals SHARED
	crypto.h
	crypto.c)

add_library(misc SHARED
	misc.h
   misc.c)

find_package(OpenSSL REQUIRED)
target_link_libraries(
	cryptopals
	OpenSSL::SSL
)

set_target_properties(
   encodings
   PROPERTIES
   PUBLIC_HEADER encodings.h
)

set_target_properties(
   cryptopals
   PROPERTIES
   PUBLIC_HEADER crypto.h
)

set_target_properties(
   misc
   PROPERTIES
   PUBLIC_HEADER misc.h
)

target_include_directories(encodings PUBLIC 
	${CMAKE_CURRENT_LIST_DIR})

target_include_directories(cryptopals PUBLIC
	${CMAKE_CURRENT_LIST_DIR})

target_include_directories(misc PUBLIC
	${CMAKE_CURRENT_LIST_DIR})
