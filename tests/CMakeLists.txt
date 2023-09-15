# Copyright (C) 2023 Intel Corporation

# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.15)

project(qat_compressor_test VERSION 0.0.1)

option(COVERAGE "Enable test coverage report" OFF)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

add_compile_definitions(NDEBUG)
add_executable(qat_compressor_test ../qat_compressor.cc qat_compressor_test.cc)

if(DEFINED QATzip_PATH)
  message(STATUS "Using QATzip_PATH: ${QATzip_PATH}")
  include_directories(${QATzip_PATH}/include)
  target_link_directories(qat_compressor_test PUBLIC ${QATzip_PATH}/src/.libs)
endif()
target_link_libraries(qat_compressor_test qatzip dl stdc++fs)

if(NOT DEFINED ROCKSDB_PATH)
  find_package(RocksDB REQUIRED)
  if(RocksDB_FOUND)
    message(STATUS "Found RocksDB: ${RocksDB_DIR}")
    target_link_libraries(qat_compressor_test RocksDB)
  endif()
else()
  message(STATUS "Using ROCKSDB_PATH: ${ROCKSDB_PATH}")
  include_directories(${ROCKSDB_PATH} ${ROCKSDB_PATH}/include)
  target_link_directories(qat_compressor_test PUBLIC ${ROCKSDB_PATH})
  target_link_libraries(qat_compressor_test rocksdb pthread)
endif()

find_package(GTest REQUIRED)
target_link_libraries(qat_compressor_test gtest)

add_compile_definitions(ROCKSDB_PLATFORM_POSIX)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fno-rtti")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-rtti")
if(COVERAGE)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} --coverage")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} --coverage")
endif()

add_custom_target(run
    COMMAND ./qat_compressor_test
    DEPENDS qat_compressor_test
)

add_custom_target(coverage
    COMMAND lcov --directory . --capture --output-file qat_compressor.info && genhtml -o html qat_compressor.info
)
