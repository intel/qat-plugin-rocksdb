// Copyright (C) 2023 Intel Corporation

// SPDX-License-Identifier: Apache-2.0

#include "../qat_compressor.h"

#include <gtest/gtest.h>

#include <cmath>
#include <filesystem>
#include <iostream>
#include <tuple>

#include "rocksdb/convenience.h"
#include "util/coding.h"

namespace ROCKSDB_NAMESPACE {

char* GenerateBlock(size_t length, int seed = 0) {
  char* buf = (char*)malloc(length);
  if (!buf) {
    return nullptr;
  }

  for (unsigned int i = 0; i < length; i++) {
    buf[i] = 'a' + ((i + seed) % 26);
  }
  return buf;
}

void DestroyBlock(char* buf) { free(buf); }

void GetPermLogDir(std::string& perm_dir_path_name) {
  Env* envptr = Env::Default();
  Status s = envptr->GetAbsolutePath("", &perm_dir_path_name);
  ASSERT_TRUE(s.ok());
}

void RemovePermLogs(void) {
  std::string perm_dir_path_name;
  GetPermLogDir(perm_dir_path_name);

  const std::filesystem::path perm_dir_path = perm_dir_path_name;
  for (auto const& perm_dir_entry :
       std::filesystem::directory_iterator{perm_dir_path}) {
    const std::filesystem::path perm_dir_entry_path = perm_dir_entry.path();
    const std::string perm_dir_entry_fname =
        perm_dir_entry_path.filename().string();
    if (perm_dir_entry_fname.rfind("qat_compressor_log_", 0) == 0) {
      std::filesystem::remove(perm_dir_entry_path);
    }
  }
}

class QATCompressorTestF : public ::testing::Test {
 protected:
  void SetUp(void) override {
    input = nullptr;
    uncompressed = nullptr;
  }

  void TearDown(void) override {
    RemovePermLogs();

    if (uncompressed != nullptr) {
      delete[] uncompressed;
    }

    if (input != nullptr) {
      DestroyBlock(input);
    }
  }

  char* input;
  char* uncompressed;
  std::string compressed;
};

TEST_F(QATCompressorTestF, CompressZeroInputSize) {
  size_t input_length = 1024;
  input = GenerateBlock(input_length);
  ASSERT_NE(input, nullptr);

  std::shared_ptr<Compressor> compressor;
  ConfigOptions config_options;
  Status s = Compressor::CreateFromString(
      config_options, "id=com.intel.qat_compressor_rocksdb", &compressor);
  ASSERT_TRUE(s.ok());

  CompressionInfo compr_info(CompressionDict::GetEmptyDict());
  Slice data(input, 0);
  s = compressor->Compress(compr_info, data, &compressed);
  EXPECT_TRUE(s.IsInvalidArgument());
}

TEST_F(QATCompressorTestF, CompressHighInputSize) {
  size_t input_length = 1024;
  input = GenerateBlock(input_length);
  ASSERT_NE(input, nullptr);

  std::shared_ptr<Compressor> compressor;
  ConfigOptions config_options;
  Status s = Compressor::CreateFromString(
      config_options, "id=com.intel.qat_compressor_rocksdb", &compressor);
  ASSERT_TRUE(s.ok());

  CompressionInfo compr_info(CompressionDict::GetEmptyDict());
  Slice data(input, (UINT_MAX + 1));
  s = compressor->Compress(compr_info, data, &compressed);
  EXPECT_TRUE(s.IsInvalidArgument());
}

class NullMemoryAllocator : public MemoryAllocator {
 public:
  static const char* kClassName(void) { return "NullMemoryAllocator"; }
  const char* Name(void) const override { return kClassName(); }

  void* Allocate(size_t /*size*/) override { return nullptr; }

  void Deallocate(void* /*p*/) override {}
};

class ExceptionMemoryAllocator : public MemoryAllocator {
 public:
  static const char* kClassName(void) { return "ExceptionMemoryAllocator"; }
  const char* Name(void) const override { return kClassName(); }

  void* Allocate(size_t /*size*/) override { throw std::bad_alloc(); }

  void Deallocate(void* /*p*/) override {}
};

TEST_F(QATCompressorTestF, CompressUncompressNullAllocator) {
  size_t input_length = 1024;
  input = GenerateBlock(input_length);
  ASSERT_NE(input, nullptr);

  std::shared_ptr<Compressor> compressor;
  ConfigOptions config_options;
  Status s = Compressor::CreateFromString(
      config_options, "id=com.intel.qat_compressor_rocksdb", &compressor);
  ASSERT_TRUE(s.ok()) << s.ToString();

  CompressionInfo compr_info(CompressionDict::GetEmptyDict());
  Slice data(input, input_length);
  s = compressor->Compress(compr_info, data, &compressed);
  ASSERT_TRUE(s.ok()) << s.ToString();

  size_t uncompressed_length;
  UncompressionInfo uncompr_info_null_allocator(
      UncompressionDict::GetEmptyDict(), 2, new NullMemoryAllocator());
  s = compressor->Uncompress(uncompr_info_null_allocator, compressed.c_str(),
                             compressed.length(), &uncompressed,
                             &uncompressed_length);
  EXPECT_TRUE(s.IsCorruption());
  EXPECT_EQ(s.ToString(), "Corruption: memory allocation error")
      << s.ToString();
}

TEST_F(QATCompressorTestF, CompressUncompressBadAllocator) {
  size_t input_length = 1024;
  input = GenerateBlock(input_length);
  ASSERT_NE(input, nullptr);

  std::shared_ptr<Compressor> compressor;
  ConfigOptions config_options;
  Status s = Compressor::CreateFromString(
      config_options, "id=com.intel.qat_compressor_rocksdb", &compressor);
  ASSERT_TRUE(s.ok()) << s.ToString();

  CompressionInfo compr_info(CompressionDict::GetEmptyDict());
  Slice data(input, input_length);
  s = compressor->Compress(compr_info, data, &compressed);
  ASSERT_TRUE(s.ok()) << s.ToString();

  size_t uncompressed_length;
  UncompressionInfo uncompr_info_exception_allocator(
      UncompressionDict::GetEmptyDict(), 2, new ExceptionMemoryAllocator());
  s = compressor->Uncompress(uncompr_info_exception_allocator,
                             compressed.c_str(), compressed.length(),
                             &uncompressed, &uncompressed_length);
  EXPECT_TRUE(s.IsCorruption());
  EXPECT_EQ(s.ToString(), "Corruption: memory allocation error")
      << s.ToString();
}

TEST_F(QATCompressorTestF, CompressUncompressLowInputSize) {
  size_t input_length = 1024;
  input = GenerateBlock(input_length);
  ASSERT_NE(input, nullptr);

  std::shared_ptr<Compressor> compressor;
  ConfigOptions config_options;
  Status s = Compressor::CreateFromString(
      config_options, "id=com.intel.qat_compressor_rocksdb", &compressor);
  ASSERT_TRUE(s.ok());

  CompressionInfo compr_info(CompressionDict::GetEmptyDict());
  Slice data(input, input_length);
  s = compressor->Compress(compr_info, data, &compressed);
  ASSERT_TRUE(s.ok()) << s.ToString();

  size_t uncompressed_length;
  UncompressionInfo uncompr_info(UncompressionDict::GetEmptyDict());
  s = compressor->Uncompress(uncompr_info, compressed.c_str(), 0, &uncompressed,
                             &uncompressed_length);
  EXPECT_TRUE(s.IsInvalidArgument());
}

TEST_F(QATCompressorTestF, CompressUncompressHighInputSize) {
  size_t input_length = 1024;
  input = GenerateBlock(input_length);
  ASSERT_NE(input, nullptr);

  std::shared_ptr<Compressor> compressor;
  ConfigOptions config_options;
  Status s = Compressor::CreateFromString(
      config_options, "id=com.intel.qat_compressor_rocksdb", &compressor);
  ASSERT_TRUE(s.ok());

  CompressionInfo compr_info(CompressionDict::GetEmptyDict());
  Slice data(input, input_length);
  s = compressor->Compress(compr_info, data, &compressed);
  ASSERT_TRUE(s.ok()) << s.ToString();

  size_t uncompressed_length;
  UncompressionInfo uncompr_info(UncompressionDict::GetEmptyDict());
  s = compressor->Uncompress(uncompr_info, compressed.c_str(), (UINT_MAX + 1),
                             &uncompressed, &uncompressed_length);
  EXPECT_TRUE(s.IsInvalidArgument());
}

TEST_F(QATCompressorTestF, CompressUncompressWrongInputSize) {
  size_t input_length = 1024;
  input = GenerateBlock(input_length);
  ASSERT_NE(input, nullptr);

  std::shared_ptr<Compressor> compressor;
  ConfigOptions config_options;
  Status s = Compressor::CreateFromString(
      config_options, "id=com.intel.qat_compressor_rocksdb", &compressor);
  ASSERT_TRUE(s.ok());

  CompressionInfo compr_info(CompressionDict::GetEmptyDict());
  Slice data(input, input_length);
  s = compressor->Compress(compr_info, data, &compressed);
  ASSERT_TRUE(s.ok()) << s.ToString();

  size_t uncompressed_length;
  UncompressionInfo uncompr_info(UncompressionDict::GetEmptyDict());
  s = compressor->Uncompress(uncompr_info, compressed.c_str(), 10,
                             &uncompressed, &uncompressed_length);
  EXPECT_TRUE(s.IsCorruption());
}

TEST_F(QATCompressorTestF, CompressUncompressWrongMetaSize) {
  size_t input_length = 1024;
  input = GenerateBlock(input_length);
  ASSERT_NE(input, nullptr);

  std::shared_ptr<Compressor> compressor;
  ConfigOptions config_options;
  Status s = Compressor::CreateFromString(
      config_options, "id=com.intel.qat_compressor_rocksdb", &compressor);
  ASSERT_TRUE(s.ok());

  CompressionInfo compr_info(CompressionDict::GetEmptyDict());
  Slice data(input, input_length);
  s = compressor->Compress(compr_info, data, &compressed);
  ASSERT_TRUE(s.ok()) << s.ToString();

  // Overwrite uncompressed size in first 4 bytes
  for (int i = 0; i < 4; i++) {
    compressed[i] = 0;
  }

  size_t uncompressed_length;
  UncompressionInfo uncompr_info(UncompressionDict::GetEmptyDict());
  s = compressor->Uncompress(uncompr_info, compressed.c_str(),
                             compressed.length(), &uncompressed,
                             &uncompressed_length);
  EXPECT_TRUE(s.IsMemoryLimit());
}

TEST_F(QATCompressorTestF, CompressNullInput) {
  std::shared_ptr<Compressor> compressor;
  ConfigOptions config_options;
  Status s = Compressor::CreateFromString(
      config_options, "id=com.intel.qat_compressor_rocksdb", &compressor);
  ASSERT_TRUE(s.ok());

  CompressionInfo compr_info(CompressionDict::GetEmptyDict());
  Slice data(nullptr, 0);
  s = compressor->Compress(compr_info, data, &compressed);
  EXPECT_TRUE(s.IsInvalidArgument());
}

TEST_F(QATCompressorTestF, CompressNullOutput) {
  size_t input_length = 1024;
  input = GenerateBlock(input_length);
  ASSERT_NE(input, nullptr);

  std::shared_ptr<Compressor> compressor;
  ConfigOptions config_options;
  Status s = Compressor::CreateFromString(
      config_options, "id=com.intel.qat_compressor_rocksdb", &compressor);
  ASSERT_TRUE(s.ok());

  CompressionInfo compr_info(CompressionDict::GetEmptyDict());
  Slice data(input, input_length);
  s = compressor->Compress(compr_info, data, nullptr);
  EXPECT_TRUE(s.IsInvalidArgument());
}

TEST_F(QATCompressorTestF, CompressUncompressNullInput) {
  std::shared_ptr<Compressor> compressor;
  ConfigOptions config_options;
  Status s = Compressor::CreateFromString(
      config_options, "id=com.intel.qat_compressor_rocksdb", &compressor);
  ASSERT_TRUE(s.ok());

  size_t uncompressed_length;
  UncompressionInfo uncompr_info(UncompressionDict::GetEmptyDict());
  s = compressor->Uncompress(uncompr_info, nullptr, 0, &uncompressed,
                             &uncompressed_length);
  EXPECT_TRUE(s.IsInvalidArgument());
}

TEST_F(QATCompressorTestF, CompressUncompressNullOutput) {
  size_t input_length = 1024;
  input = GenerateBlock(input_length);
  ASSERT_NE(input, nullptr);

  std::shared_ptr<Compressor> compressor;
  ConfigOptions config_options;
  Status s = Compressor::CreateFromString(
      config_options, "id=com.intel.qat_compressor_rocksdb", &compressor);
  ASSERT_TRUE(s.ok());

  CompressionInfo compr_info(CompressionDict::GetEmptyDict());
  Slice data(input, input_length);
  s = compressor->Compress(compr_info, data, &compressed);
  ASSERT_TRUE(s.ok()) << s.ToString();

  size_t uncompressed_length;
  UncompressionInfo uncompr_info(UncompressionDict::GetEmptyDict());
  s = compressor->Uncompress(uncompr_info, compressed.c_str(),
                             compressed.length(), nullptr,
                             &uncompressed_length);
  EXPECT_TRUE(s.IsInvalidArgument());
}

TEST_F(QATCompressorTestF, CompressUncompressNullOutputSize) {
  size_t input_length = 1024;
  input = GenerateBlock(input_length);
  ASSERT_NE(input, nullptr);

  std::shared_ptr<Compressor> compressor;
  ConfigOptions config_options;
  Status s = Compressor::CreateFromString(
      config_options, "id=com.intel.qat_compressor_rocksdb", &compressor);
  ASSERT_TRUE(s.ok());

  CompressionInfo compr_info(CompressionDict::GetEmptyDict());
  Slice data(input, input_length);
  s = compressor->Compress(compr_info, data, &compressed);
  ASSERT_TRUE(s.ok()) << s.ToString();

  size_t uncompressed_length;
  UncompressionInfo uncompr_info(UncompressionDict::GetEmptyDict());
  s = compressor->Uncompress(uncompr_info, compressed.c_str(),
                             compressed.length(), &uncompressed, nullptr);
  EXPECT_TRUE(s.IsInvalidArgument());
}

void VerifyNoPermLog(void) {
  std::string perm_dir_path_name;
  GetPermLogDir(perm_dir_path_name);

  const std::filesystem::path perm_dir_path = perm_dir_path_name;
  for (auto const& perm_dir_entry :
       std::filesystem::directory_iterator{perm_dir_path}) {
    const std::string perm_dir_entry_fname =
        perm_dir_entry.path().filename().string();
    ASSERT_TRUE(perm_dir_entry_fname.rfind("qat_compressor_log_", 0) != 0);
  }
}

void VerifyMinPermLogPerms(void) {
  std::string perm_dir_path_name;
  GetPermLogDir(perm_dir_path_name);

  bool perm_log_has_min_perms = false;
  const std::filesystem::path perm_dir_path = perm_dir_path_name;
  for (auto const& perm_dir_entry :
       std::filesystem::directory_iterator{perm_dir_path}) {
    const std::string perm_dir_entry_fname =
        perm_dir_entry.path().filename().string();
    if (perm_dir_entry_fname.rfind("qat_compressor_log_", 0) == 0) {
      const std::filesystem::perms perm_dir_entry_perms =
          perm_dir_entry.status().permissions();
      perm_log_has_min_perms =
          ((perm_dir_entry_perms & std::filesystem::perms::owner_read) !=
               std::filesystem::perms::none &&
           (perm_dir_entry_perms & std::filesystem::perms::owner_write) !=
               std::filesystem::perms::none &&
           (perm_dir_entry_perms & std::filesystem::perms::owner_exec) ==
               std::filesystem::perms::none &&
           (perm_dir_entry_perms & std::filesystem::perms::group_read) !=
               std::filesystem::perms::none &&
           (perm_dir_entry_perms & std::filesystem::perms::group_write) ==
               std::filesystem::perms::none &&
           (perm_dir_entry_perms & std::filesystem::perms::group_exec) ==
               std::filesystem::perms::none &&
           (perm_dir_entry_perms & std::filesystem::perms::others_read) !=
               std::filesystem::perms::none &&
           (perm_dir_entry_perms & std::filesystem::perms::others_write) ==
               std::filesystem::perms::none &&
           (perm_dir_entry_perms & std::filesystem::perms::others_exec) ==
               std::filesystem::perms::none);
    }
  }

  ASSERT_TRUE(perm_log_has_min_perms);
}

TEST_F(QATCompressorTestF, CheckPermLogFilePerms) {
  VerifyNoPermLog();

  std::shared_ptr<Compressor> compressor;
  ConfigOptions config_options;
  Status s = Compressor::CreateFromString(
      config_options, "id=com.intel.qat_compressor_rocksdb", &compressor);
  ASSERT_TRUE(s.ok());

  VerifyMinPermLogPerms();
}

TEST_F(QATCompressorTestF, CompressOverflowInputSize) {
  size_t input_length = 1024;
  input = GenerateBlock(input_length);
  ASSERT_NE(input, nullptr);

  std::shared_ptr<Compressor> compressor;
  ConfigOptions config_options;
  Status s = Compressor::CreateFromString(
      config_options, "id=com.intel.qat_compressor_rocksdb", &compressor);
  ASSERT_TRUE(s.ok());

  CompressionInfo compr_info(CompressionDict::GetEmptyDict());
  Slice data(input, UINT_MAX);
  s = compressor->Compress(compr_info, data, &compressed);
  EXPECT_TRUE(s.IsInvalidArgument());
}

TEST_F(QATCompressorTestF, CheckPermLogFileRemoved) {
  VerifyNoPermLog();

  std::shared_ptr<Compressor> compressor;
  ConfigOptions config_options;
  Status s = Compressor::CreateFromString(
      config_options, "id=com.intel.qat_compressor_rocksdb", &compressor);
  ASSERT_TRUE(s.ok());

  compressor.reset();
  VerifyNoPermLog();
}

TEST_F(QATCompressorTestF, InitAttemptInvalidOptions) {
  std::string invalid_options =
      "id=com.intel.qat_compressor_rocksdb;"
      "huffman_hdr=aaa;data_fmt=aaa;"
      "comp_algorithm=aaa;sw_backup=aaa";

  // If not ignoring unknown options, an error will be reported
  std::shared_ptr<Compressor> compressor;
  ConfigOptions config_options;
  Status s = Compressor::CreateFromString(config_options, invalid_options,
                                          &compressor);
  EXPECT_TRUE(s.IsInvalidArgument());
}

TEST_F(QATCompressorTestF, InitDefaultOptions) {
  std::shared_ptr<Compressor> compressor;
  ConfigOptions config_options;
  Status s = Compressor::CreateFromString(
      config_options, "id=com.intel.qat_compressor_rocksdb", &compressor);
  ASSERT_TRUE(s.ok());

  std::string value;
  s = compressor->GetOption(config_options, "huffman_hdr", &value);
  EXPECT_TRUE(s.ok());
  EXPECT_EQ(value, "dynamic");
  s = compressor->GetOption(config_options, "data_fmt", &value);
  EXPECT_TRUE(s.ok());
  EXPECT_EQ(value, "deflate_gzip_ext");
  s = compressor->GetOption(config_options, "comp_algorithm", &value);
  EXPECT_TRUE(s.ok());
  EXPECT_EQ(value, "deflate");
  s = compressor->GetOption(config_options, "sw_backup", &value);
  EXPECT_TRUE(s.ok());
  EXPECT_EQ(value, "enable");
}

TEST_F(QATCompressorTestF, InitIgnoreInvalidOptions) {
  std::string invalid_options =
      "id=com.intel.qat_compressor_rocksdb;"
      "huffman_hdr=aaa;data_fmt=aaa;"
      "comp_algorithm=aaa;sw_backup=aaa";

  // If ignoring unknown options, options will be default
  std::shared_ptr<Compressor> compressor;
  ConfigOptions config_options;
  config_options.ignore_unknown_options = true;
  Status s = Compressor::CreateFromString(config_options, invalid_options,
                                          &compressor);
  ASSERT_TRUE(s.ok());

  std::string value;
  s = compressor->GetOption(config_options, "huffman_hdr", &value);
  EXPECT_TRUE(s.ok());
  EXPECT_EQ(value, "dynamic");
  s = compressor->GetOption(config_options, "data_fmt", &value);
  EXPECT_TRUE(s.ok());
  EXPECT_EQ(value, "deflate_gzip_ext");
  s = compressor->GetOption(config_options, "comp_algorithm", &value);
  EXPECT_TRUE(s.ok());
  EXPECT_EQ(value, "deflate");
  s = compressor->GetOption(config_options, "sw_backup", &value);
  EXPECT_TRUE(s.ok());
  EXPECT_EQ(value, "enable");
}

TEST_F(QATCompressorTestF, InitNonDefaultOptions) {
  std::shared_ptr<Compressor> compressor;
  ConfigOptions config_options;
  Status s =
      Compressor::CreateFromString(config_options,
                                   "id=com.intel.qat_compressor_rocksdb;"
                                   "comp_algorithm=lz4;sw_backup=disable",
                                   &compressor);
  ASSERT_TRUE(s.ok());

  std::string value;
  s = compressor->GetOption(config_options, "comp_algorithm", &value);
  EXPECT_TRUE(s.ok());
  EXPECT_EQ(value, "lz4");
  s = compressor->GetOption(config_options, "sw_backup", &value);
  EXPECT_TRUE(s.ok());
  EXPECT_EQ(value, "disable");
}

TEST_F(QATCompressorTestF, CompressUncompressDefaultAllocator) {
  size_t input_length = 1024;
  input = GenerateBlock(input_length);
  ASSERT_NE(input, nullptr);

  std::shared_ptr<Compressor> compressor;
  ConfigOptions config_options;
  Status s = Compressor::CreateFromString(
      config_options, "id=com.intel.qat_compressor_rocksdb", &compressor);
  ASSERT_TRUE(s.ok()) << s.ToString();

  CompressionInfo compr_info(CompressionDict::GetEmptyDict());
  Slice data(input, input_length);
  s = compressor->Compress(compr_info, data, &compressed);
  ASSERT_TRUE(s.ok()) << s.ToString();

  size_t uncompressed_length;
  UncompressionInfo uncompr_info_default_allocator(
      UncompressionDict::GetEmptyDict(), 2);
  s = compressor->Uncompress(uncompr_info_default_allocator, compressed.c_str(),
                             compressed.length(), &uncompressed,
                             &uncompressed_length);
  EXPECT_TRUE(s.ok()) << s.ToString();
}

struct TestParam {
  TestParam(const char* _comp_algorithm, const char* _data_fmt,
            const char* _huffman_hdr, unsigned int _comp_lvl,
            const char* _sw_backup, const char* _polling_mode,
            size_t _block_size, unsigned int _num_blocks = 1)
      : comp_algorithm(_comp_algorithm),
        data_fmt(_data_fmt),
        huffman_hdr(_huffman_hdr),
        comp_lvl(_comp_lvl),
        sw_backup(_sw_backup),
        polling_mode(_polling_mode),
        block_size(_block_size),
        num_blocks(_num_blocks) {}

  std::string comp_algorithm;
  std::string data_fmt;
  std::string huffman_hdr;
  unsigned int comp_lvl;
  std::string sw_backup;
  std::string polling_mode;
  size_t block_size;
  unsigned int num_blocks;

  std::string GetOpts(void) {
    return "comp_algorithm=" + comp_algorithm + ";data_fmt=" + data_fmt +
           ";huffman_hdr=" + huffman_hdr +
           ";comp_lvl=" + std::to_string(comp_lvl) + ";sw_backup=" + sw_backup +
           ";polling_mode=" + polling_mode;
  }
};

class QATCompressorTestP
    : public testing::TestWithParam<
          std::tuple<const char*, const char*, const char*, unsigned int,
                     const char*, const char*, size_t, unsigned int>> {
 public:
  static void SetUpTestSuite(void) {
    ObjectLibrary::Default()->AddFactory<Compressor>(
        "com.intel.qat_compressor_rocksdb",
        [](const std::string& /* uri */, std::unique_ptr<Compressor>* c,
           std::string* /* errmsg */) {
          c->reset(NewQATCompressor().get());
          return c->get();
        });
  }

  void SetUp(void) override {
    TestParam test_param(std::get<0>(GetParam()), std::get<1>(GetParam()),
                         std::get<2>(GetParam()), std::get<3>(GetParam()),
                         std::get<4>(GetParam()), std::get<5>(GetParam()),
                         std::get<6>(GetParam()), std::get<7>(GetParam()));
    ConfigOptions config_options;
    s = Compressor::CreateFromString(
        config_options,
        "id=com.intel.qat_compressor_rocksdb;" + test_param.GetOpts(),
        &compressor);

    input_length = test_param.block_size;
    input = GenerateBlock(input_length);
    uncompressed = nullptr;
  }

  void TearDown(void) override {
    RemovePermLogs();

    if (uncompressed != nullptr) {
      delete[] uncompressed;
    }

    if (input != nullptr) {
      DestroyBlock(input);
    }
  }

  Status s;
  char* input;
  size_t input_length;
  char* uncompressed;
  size_t uncompressed_length;
  std::string compressed;
  std::shared_ptr<Compressor> compressor;
};

TEST_P(QATCompressorTestP, CompressUncompress) {
  ASSERT_TRUE(s.ok());
  ASSERT_NE(input, nullptr);

  CompressionInfo compr_info(CompressionDict::GetEmptyDict());
  Slice data(input, input_length);
  s = compressor->Compress(compr_info, data, &compressed);
  ASSERT_TRUE(s.ok()) << s.ToString();

  UncompressionInfo uncompr_info(UncompressionDict::GetEmptyDict());
  s = compressor->Uncompress(uncompr_info, compressed.c_str(),
                             compressed.length(), &uncompressed,
                             &uncompressed_length);
  ASSERT_TRUE(s.ok()) << s.ToString();
  ASSERT_EQ(uncompressed_length, input_length);
  ASSERT_TRUE(memcmp(uncompressed, input, input_length) == 0);
}

#define BLOCK_SIZES                                                       \
  100, 1 << 8, 1000, 1 << 10, 1 << 12, 1 << 14, 1 << 16, 100000, 1000000, \
      1 << 20

INSTANTIATE_TEST_SUITE_P(
    CompressUncompressDeflate, QATCompressorTestP,
    testing::Combine(testing::Values("deflate"),
                     testing::Values("deflate_4b", "deflate_gzip",
                                     "deflate_gzip_ext", "deflate_raw"),
                     testing::Values("dynamic", "static"),
                     testing::Values(1, 2, 3, 4, 5, 6, 7, 8, 9),
                     testing::Values("enable", "disable"),
                     testing::Values("periodical", "busy"),
                     testing::Values(BLOCK_SIZES), testing::Values(1)));

INSTANTIATE_TEST_SUITE_P(
    CompressUncompressLz4, QATCompressorTestP,
    testing::Combine(testing::Values("lz4"),
                     testing::Values("deflate_raw"),  // Unused
                     testing::Values("static"),       // Unused
                     testing::Values(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12),
                     testing::Values("enable", "disable"),
                     testing::Values("periodical", "busy"),
                     testing::Values(BLOCK_SIZES), testing::Values(1)));

void VerifyNoSymlinkPermLog(void) {
  std::string perm_dir_path_name;
  GetPermLogDir(perm_dir_path_name);

  bool perm_log_not_symlink = false;
  const std::filesystem::path perm_dir_path = perm_dir_path_name;
  for (auto const& perm_dir_entry :
       std::filesystem::directory_iterator{perm_dir_path}) {
    const std::string perm_dir_entry_fname =
        perm_dir_entry.path().filename().string();
    if (perm_dir_entry_fname.rfind("qat_compressor_log_", 0) == 0) {
      perm_log_not_symlink = !perm_dir_entry.is_symlink();
    }
  }

  ASSERT_TRUE(perm_log_not_symlink);
}

TEST_F(QATCompressorTestF, CheckPermLogFileNotSymlink) {
  VerifyNoPermLog();

  std::shared_ptr<Compressor> compressor;
  ConfigOptions config_options;
  Status s = Compressor::CreateFromString(
      config_options, "id=com.intel.qat_compressor_rocksdb", &compressor);
  ASSERT_TRUE(s.ok());

  VerifyNoSymlinkPermLog();
}
}  // namespace ROCKSDB_NAMESPACE

int main(int argc, char* argv[]) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
