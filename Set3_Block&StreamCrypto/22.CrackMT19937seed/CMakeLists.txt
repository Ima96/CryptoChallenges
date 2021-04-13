cmake_minimum_required (VERSION 3.16)
project (Challenge22)

add_executable (run main.cpp)

find_package(OpenSSL REQUIRED)
find_package(RandomLib 1.9 REQUIRED)
include_directories (${RandomLib_INCLUDE_DIRS})
target_link_libraries(run OpenSSL::SSL ${RandomLib_LIBRARIES})