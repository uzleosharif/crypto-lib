cmake_minimum_required(VERSION 3.22)

project(crypto-lib CXX)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_FLAGS "-Wall")


add_library(crypto SHARED src/sha.cpp)
target_include_directories(crypto PUBLIC 
  $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include/>
)
export(
  TARGETS crypto 
  NAMESPACE uz::
  FILE ${CMAKE_CURRENT_BINARY_DIR}/CryptoLibraryTargets.cmake
)

add_library(uz::crypto ALIAS crypto)

add_subdirectory(examples/)
add_subdirectory(test/)
