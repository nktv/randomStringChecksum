cmake_minimum_required(VERSION 3.10)
project(exasol)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_VERBOSE_MAKEFILE ON)


file(GLOB_RECURSE SOURCE_FILES "source/*.cpp" main.cpp "source/sha1.c")

add_compile_options(-O2 -g -pthread)

add_executable(exasol)
target_include_directories(exasol PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/headers)
target_sources(exasol PRIVATE ${SOURCE_FILES})
target_link_libraries(exasol PRIVATE -lssl -lcrypto)
