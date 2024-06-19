



cmake_minimum_required(VERSION 3.22)

project(crypto-test CXX)

add_subdirectory(catch2/)

set(CMAKE_CXX_FLAGS "-DCATCH_CONFIG_MAIN")

add_executable(tests sha_test.cpp)
target_link_libraries(tests PRIVATE uz::crypto Catch2::Catch2WithMain)
