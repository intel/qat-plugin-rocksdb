# Copyright (C) 2023 Intel Corporation

# SPDX-License-Identifier: Apache-2.0

qat_compressor_SOURCES = qat_compressor.cc
qat_compressor_HEADERS = qat_compressor.h
qat_compressor_LDFLAGS = -lqatzip -u qat_compressor_reg
