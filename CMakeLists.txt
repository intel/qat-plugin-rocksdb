# Copyright (C) 2023 Intel Corporation

# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.4)

set(qat_compressor_SOURCES "qat_compressor.cc" PARENT_SCOPE)
set(qat_compressor_INCLUDE_PATHS "${QATzip_PATH}/include" PARENT_SCOPE)
set(qat_compressor_LINK_PATHS "${QATzip_PATH}/src/.libs" PARENT_SCOPE)
set(qat_compressor_LIBS "qatzip;dl" PARENT_SCOPE)
set(qat_compressor_CMAKE_EXE_LINKER_FLAGS "-u qat_compressor_reg" PARENT_SCOPE)
