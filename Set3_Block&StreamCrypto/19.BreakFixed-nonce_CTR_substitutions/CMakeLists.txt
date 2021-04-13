cmake_minimum_required (VERSION 3.16)
project (Challenge19)

add_executable (run main.cpp)

find_package(OpenSSL REQUIRED)
target_link_libraries(run OpenSSL::SSL)