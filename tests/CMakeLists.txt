cmake_minimum_required(VERSION 3.20)

set(TARGET cryptopals_tests)

project(${TARGET})

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(EXTERNAL_INSTALL_LOCATION ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/googletest)

include(ExternalProject)
ExternalProject_Add(googletest
   GIT_REPOSITORY https://github.com/google/googletest
   GIT_TAG  main
   CMAKE_ARGS -DCMAKE_INSTALL_PREFIX=${EXTERNAL_INSTALL_LOCATION}
)

include_directories(${EXTERNAL_INSTALL_LOCATION}/include)
link_directories(${EXTERNAL_INSTALL_LOCATION}/lib)

add_executable(
   ${TARGET} 
   ${CMAKE_CURRENT_LIST_DIR}/src/tests.cpp
)

add_dependencies(${TARGET} googletest)
target_link_libraries(
   ${TARGET} 
      gtest 
      gtest_main
      pthread
      cryptopals
)