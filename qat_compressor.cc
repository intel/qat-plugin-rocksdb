// Copyright (C) 2023 Intel Corporation

// SPDX-License-Identifier: Apache-2.0

#include "qat_compressor.h"

#include <qatzip.h>

#include <climits>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <unordered_map>

#include "logging/logging.h"
#include "rocksdb/compressor.h"
#include "rocksdb/configurable.h"
#include "rocksdb/env.h"
#include "rocksdb/utilities/options_type.h"
#include "util/coding.h"

using namespace ROCKSDB_NAMESPACE;

namespace ROCKSDB_NAMESPACE {

// Error messages
#define MEMORY_ALLOCATION_ERROR "memory allocation error"

extern "C" FactoryFunc<Compressor> qat_compressor_reg;

FactoryFunc<Compressor> qat_compressor_reg =
    ObjectLibrary::Default()->AddFactory<Compressor>(
        "com.intel.qat_compressor_rocksdb",
        [](const std::string& /* uri */,
           std::unique_ptr<Compressor>* compressor, std::string* /* errmsg */) {
          *compressor = NewQATCompressor();
          return compressor->get();
        });

std::unordered_map<std::string, QzHuffmanHdr_T> huffman_hdr_lookup = {
    {"dynamic", QZ_DYNAMIC_HDR}, {"static", QZ_STATIC_HDR}};

std::unordered_map<std::string, QzDataFormat_T> data_fmt_lookup = {
    {"deflate_4b", QZ_DEFLATE_4B},
    {"deflate_gzip", QZ_DEFLATE_GZIP},
    {"deflate_gzip_ext", QZ_DEFLATE_GZIP_EXT},
    {"deflate_raw", QZ_DEFLATE_RAW}};

std::unordered_map<std::string, unsigned char> comp_algorithm_lookup = {
    {"deflate", QZ_DEFLATE}, {"lz4", QZ_LZ4}};

std::unordered_map<std::string, unsigned char> sw_backup_lookup = {
    {"disable", 0}, {"enable", 1}};

std::unordered_map<std::string, QzPollingMode_T> polling_mode_lookup = {
    {"periodical", QZ_PERIODICAL_POLLING}, {"busy", QZ_BUSY_POLLING}};

struct QATCompressorOptions {
  static const char* kName() { return "QATCompressorOptions"; }

  // Header specifying which Huffman tree type to use
  // Choice only matters if DEFLATE algorithm is used
  QzHuffmanHdr_T huffman_hdr = QZ_HUFF_HDR_DEFAULT;

  // Format of compressed data
  QzDataFormat_T data_fmt = QZ_DATA_FORMAT_DEFAULT;

  // Level of compression to apply (1 to 12 for LZ4 and 1 to 9 for DEFLATE)
  // Higher levels are more computationally expensive
  unsigned int comp_lvl = QZ_COMP_LEVEL_DEFAULT;

  // Compression algorithm that is used
  // Note that this is separate from the data format
  unsigned char comp_algorithm = QZ_COMP_ALGOL_DEFAULT;

  // If = 1, enable sw path
  // If = 0, disable sw path
  unsigned char sw_backup = QZ_SW_BACKUP_DEFAULT;

  // Buffer size hw instance is capable of processing
  // If possible, make it a multiple of the page size
  unsigned int hw_buff_sz = QZ_HW_BUFF_SZ;

  // Buffer size limit when streaming APIs are used
  unsigned int strm_buff_sz = QZ_STRM_BUFF_SZ_DEFAULT;

  // Buffer input size limit
  // Any request below this value will route to software
  unsigned int input_sz_thrshold = QZ_COMP_THRESHOLD_DEFAULT;

  // Limit on the number of attempts to acquire hw before giving up
  unsigned int wait_cnt_thrshold = QZ_WAIT_CNT_THRESHOLD_DEFAULT;

  // Specifies polling mechanism for waiting on results from device(s)
  QzPollingMode_T polling_mode = QZ_PERIODICAL_POLLING;

  // Specifies sensitivity mode
  unsigned int is_sensitive_mode = 0;

  // Keep retrying after unsuccesful attempts at acquiring hardware
  bool retry = false;
};

static OptionTypeInfo huffman_hdr_entry = OptionTypeInfo::Enum(
    offsetof(struct QATCompressorOptions, huffman_hdr), &huffman_hdr_lookup);

static OptionTypeInfo data_fmt_entry = OptionTypeInfo::Enum(
    offsetof(struct QATCompressorOptions, data_fmt), &data_fmt_lookup);

static OptionTypeInfo comp_lvl_entry = {
    offsetof(struct QATCompressorOptions, comp_lvl), OptionType::kUInt,
    OptionVerificationType::kNormal, OptionTypeFlags::kNone};

static OptionTypeInfo comp_algorithm_entry =
    OptionTypeInfo::Enum(offsetof(struct QATCompressorOptions, comp_algorithm),
                         &comp_algorithm_lookup);

static OptionTypeInfo sw_backup_entry = OptionTypeInfo::Enum(
    offsetof(struct QATCompressorOptions, sw_backup), &sw_backup_lookup);

static OptionTypeInfo hw_buff_sz_entry = {
    offsetof(struct QATCompressorOptions, hw_buff_sz), OptionType::kUInt,
    OptionVerificationType::kNormal, OptionTypeFlags::kNone};

static OptionTypeInfo strm_buff_sz_entry = {
    offsetof(struct QATCompressorOptions, strm_buff_sz), OptionType::kUInt,
    OptionVerificationType::kNormal, OptionTypeFlags::kNone};

static OptionTypeInfo input_sz_thrshold_entry = {
    offsetof(struct QATCompressorOptions, input_sz_thrshold), OptionType::kUInt,
    OptionVerificationType::kNormal, OptionTypeFlags::kNone};

static OptionTypeInfo wait_cnt_thrshold_entry = {
    offsetof(struct QATCompressorOptions, wait_cnt_thrshold), OptionType::kUInt,
    OptionVerificationType::kNormal, OptionTypeFlags::kNone};

static OptionTypeInfo polling_mode_entry = OptionTypeInfo::Enum(
    offsetof(struct QATCompressorOptions, polling_mode), &polling_mode_lookup);

static OptionTypeInfo retry_entry = {
    offsetof(struct QATCompressorOptions, retry), OptionType::kBoolean,
    OptionVerificationType::kNormal, OptionTypeFlags::kNone};

static std::unordered_map<std::string, OptionTypeInfo>
    qat_compressor_type_info = {{"huffman_hdr", huffman_hdr_entry},
                                {"data_fmt", data_fmt_entry},
                                {"comp_lvl", comp_lvl_entry},
                                {"comp_algorithm", comp_algorithm_entry},
                                {"sw_backup", sw_backup_entry},
                                {"hw_buff_sz", hw_buff_sz_entry},
                                {"strm_buff_sz", strm_buff_sz_entry},
                                {"input_sz_thrshold", input_sz_thrshold_entry},
                                {"wait_cnt_thrshold", wait_cnt_thrshold_entry},
                                {"polling_mode", polling_mode_entry},
                                {"retry", retry_entry}};

class QATCompressor : public Compressor {
 public:
  QATCompressor(void) {
    RegisterOptions(&options_, &qat_compressor_type_info);

    // Get absolute log directory name
    std::string full_log_dname;
    Env* envptr = Env::Default();
    Status s = envptr->GetAbsolutePath("", &full_log_dname);
    if (!s.ok()) {
      throw std::runtime_error("failed to get full log directory");
    }

    // Generate a unique log file name
    std::string base_log_fname =
        "qat_compressor_log_" + envptr->GenerateUniqueId() + ".txt";
    perm_log_fname_ = full_log_dname + "/" + base_log_fname;

    // Create a new logger object
    s = envptr->NewLogger(perm_log_fname_, &logger_);
    if (s.ok()) {
#ifndef NDEBUG
      logger_->SetInfoLogLevel(DEBUG_LEVEL);
#else
      logger_->SetInfoLogLevel(WARN_LEVEL);
#endif
    } else {
      throw std::runtime_error("failed to create new logger object");
    }
  }

  ~QATCompressor(void) {
    int status;
    const std::lock_guard<std::mutex> session_lock(session_mutex_);

    // De-initialize and close all QATzip sessions
    for (auto iter = sessions_.begin(); iter != sessions_.end(); iter++) {
      Debug(logger_, "Terminating session %p\n", iter->second);

      status = qzTeardownSession(iter->second);
      if (status != QZ_OK) {
        Warn(logger_, "qzTeardownSession() call for session %p returned %d\n",
             iter->second, status);
      }

      status = qzClose(iter->second);
      if (status != QZ_OK) {
        Warn(logger_, "qzClose() call for session %p returned %d\n",
             iter->second, status);
      }

      delete iter->second;
    }

    // Clear all sessions
    sessions_.clear();

    // Close the logger
    Status s = logger_->Close();
    bool del_perm_log_file = false;
    if (!s.ok()) {
      del_perm_log_file = true;
    }

    // Get the log file size
    uint64_t perm_log_file_size;
    Env* envptr = Env::Default();
    s = envptr->GetFileSize(perm_log_fname_, &perm_log_file_size);
    if (!s.ok() || perm_log_file_size == 0) {
      del_perm_log_file = true;
    }

    // Delete the log file if it's empty or something went wrong
    if (del_perm_log_file) {
      envptr->DeleteFile(perm_log_fname_);
    }
  }

  static const char* kClassName(void) {
    return "com.intel.qat_compressor_rocksdb";
  }

  const char* Name(void) const override { return kClassName(); }

  bool DictCompressionSupported(void) const override { return false; }

  Status Compress(const CompressionInfo& info, const Slice& input,
                  std::string* output) override {
    (void)info;

    // Make sure input and output buffers aren't NULL
    if (input.data() == nullptr) {
      Error(logger_, "Input data pointer is NULL\n");
      return Status::InvalidArgument();
    } else if (output == nullptr) {
      Error(logger_, "Output data pointer is NULL\n");
      return Status::InvalidArgument();
    }

    // Make sure input buffer size is small enough to handle
    if (input.size() > UINT_MAX) {
      Error(logger_, "Input data size (%lu bytes) is too large\n",
            input.size());
      return Status::InvalidArgument();
    }

    // Get the session handle
    QzSession_T* sess = nullptr;
    Status s = FindSession(&sess);
    if (!s.ok()) {
      return s;
    }

    // Calculate destination buffer size
    // Cast from size_t to uint is okay because of prior limit check
    unsigned int src_buf_size = static_cast<unsigned int>(input.size());
    unsigned int dst_buf_size = qzMaxCompressedLength(src_buf_size, sess);
    if (dst_buf_size == 0) {
      Error(logger_, "qzMaxCompressedLength() call encountered overflow\n");
      return Status::InvalidArgument();
    } else if (dst_buf_size == QZ_COMPRESSED_SZ_OF_EMPTY_FILE) {
      Error(logger_,
            "qzMaxCompressedLength() call encountered empty source buffer "
            "size\n");
      return Status::InvalidArgument();
    }

    // Max size of a RocksDB block is 4GiB
    uint32_t output_hdr_len = EncodeSize(input.size(), output);

    // Resize the output buffer
    // Cast from uint to size_t is okay because no data loss occurs
    size_t conv_size =
        static_cast<size_t>(dst_buf_size) + static_cast<size_t>(output_hdr_len);
    s = ResizeBuffer(output, conv_size);
    if (!s.ok()) {
      return s;
    }

    // Find source and destination buffers
    // Cast from char* to unsigned char* is okay because type size is the same
    unsigned char* src_buf =
        reinterpret_cast<unsigned char*>(const_cast<char*>(input.data()));
    unsigned char* dst_buf =
        reinterpret_cast<unsigned char*>(&(*output)[0] + output_hdr_len);

    // Compress source data
    unsigned int src_buf_pos = 0;
    unsigned int dst_buf_pos = 0;
    while (src_buf_pos < src_buf_size) {
      unsigned int src_buf_size_proxy = src_buf_size - src_buf_pos;
      unsigned int dst_buf_size_proxy = dst_buf_size - dst_buf_pos;
      unsigned char* src_buf_proxy = &(src_buf[src_buf_pos]);
      unsigned char* dst_buf_proxy = &(dst_buf[dst_buf_pos]);
      int status = qzCompress(sess, src_buf_proxy, &src_buf_size_proxy,
                              dst_buf_proxy, &dst_buf_size_proxy, 1);
      if (status == QZ_NOSW_NO_INST_ATTACH && options_.retry) {
        // Couldn't find a QAT compression instance, so try again
        continue;
      } else if (status != QZ_OK) {
        Error(logger_, "qzCompress() call returned %d\n", status);
        return ParseErrCodeQZ(status);
      }

      // Update trackers
      src_buf_pos += src_buf_size_proxy;
      dst_buf_pos += dst_buf_size_proxy;

      Debug(logger_,
            "Session %p compressed %u bytes into %u bytes with %u bytes "
            "remaining\n",
            sess, src_buf_size_proxy, dst_buf_size_proxy,
            (src_buf_size - src_buf_pos));
    }

    // Set the correct output buffer size
    // Cast from uint to size_t is okay because no data loss occurs
    conv_size =
        static_cast<size_t>(dst_buf_pos) + static_cast<size_t>(output_hdr_len);
    s = ResizeBuffer(output, conv_size);
    if (!s.ok()) {
      return s;
    }

    return Status::OK();
  }

  Status Uncompress(const UncompressionInfo& info, const char* input,
                    size_t input_length, char** output,
                    size_t* output_length) override {
    // Make sure the input and output buffers aren't NULL
    if (input == nullptr) {
      Error(logger_, "Input data pointer is NULL\n");
      return Status::InvalidArgument();
    } else if (output == nullptr) {
      Error(logger_, "Output data pointer is NULL\n");
      return Status::InvalidArgument();
    } else if (output_length == nullptr) {
      Error(logger_, "Output length pointer is NULL\n");
      return Status::InvalidArgument();
    }

    // Make sure input buffer size is acceptable
    if (input_length <= sizeof(uint32_t)) {
      Error(logger_, "Input data size (%lu bytes) is too small\n",
            input_length);
      return Status::InvalidArgument();
    } else if (input_length > UINT_MAX) {
      Error(logger_, "Input data size (%lu bytes) is too large\n",
            input_length);
      return Status::InvalidArgument();
    }

    // Extract uncompressed size
    uint32_t enc_output_len = 0;
    bool res = DecodeSize(&input, &input_length, &enc_output_len);
    if (!res) {
      return Status::Corruption("size decoding error");
    }

    // Make sure destination buffer size is small enough to handle
    if (enc_output_len > UINT_MAX) {
      Error(logger_, "Output data size (%u bytes) is too large\n",
            enc_output_len);
      return Status::InvalidArgument();
    }

    // Get the session handle
    QzSession_T* sess = nullptr;
    Status s = FindSession(&sess);
    if (!s.ok()) {
      return s;
    }

    // Set source and destination buffer sizes
    // Cast from size_t to uint is okay because of prior limit check
    // Cast from uint32_t to uint is okay because of prior limit check
    unsigned int src_buf_size = static_cast<unsigned int>(input_length);
    unsigned int dst_buf_size = static_cast<unsigned int>(enc_output_len);

    // Memory allocator may return null pointer or throw bad_alloc exception
    try {
      *output = Allocate(enc_output_len, info.GetMemoryAllocator());
      if (*output == nullptr) {
        return Status::Corruption(MEMORY_ALLOCATION_ERROR);
      }
    } catch (std::bad_alloc& e) {
      return Status::Corruption(MEMORY_ALLOCATION_ERROR);
    }

    // Find source and destination buffers
    // Cast from char* to unsigned char* is okay because type size is the same
    unsigned char* src_buf =
        reinterpret_cast<unsigned char*>(const_cast<char*>(input));
    unsigned char* dst_buf = reinterpret_cast<unsigned char*>(*output);

    // Decompress source data
    unsigned int src_buf_pos = 0;
    unsigned int dst_buf_pos = 0;
    while (src_buf_pos < src_buf_size) {
      unsigned int src_buf_size_proxy = src_buf_size - src_buf_pos;
      unsigned int dst_buf_size_proxy = dst_buf_size - dst_buf_pos;
      unsigned char* src_buf_proxy = &(src_buf[src_buf_pos]);
      unsigned char* dst_buf_proxy = &(dst_buf[dst_buf_pos]);
      int status = qzDecompress(sess, src_buf_proxy, &src_buf_size_proxy,
                                dst_buf_proxy, &dst_buf_size_proxy);
      if (status == QZ_NOSW_NO_INST_ATTACH && options_.retry) {
        // Couldn't find a QAT compression instance, so try again
        continue;
      } else if (status != QZ_OK) {
        Error(logger_, "qzDecompress() call returned %d\n", status);
        return ParseErrCodeQZ(status);
      }

      // Update trackers
      src_buf_pos += src_buf_size_proxy;
      dst_buf_pos += dst_buf_size_proxy;
      Debug(logger_,
            "Session %p decompressed %u bytes into %u bytes with %u bytes "
            "remaining\n",
            sess, src_buf_size_proxy, dst_buf_size_proxy,
            (src_buf_size - src_buf_pos));
    }

    // Make sure amount of decompressed data matches original size
    if (dst_buf_pos != dst_buf_size) {
      return Status::Corruption("size mismatch");
    }

    // Set output buffer length
    // Cast from uint to size_t is okay because no data loss occurs
    *output_length = static_cast<size_t>(dst_buf_pos);

    return Status::OK();
  }

 private:
  // Metadata
  QATCompressorOptions options_;
  std::shared_ptr<Logger> logger_;
  std::string perm_log_fname_;
  std::unordered_map<std::thread::id, QzSession_T*> sessions_;

  // Access Control
  std::mutex session_mutex_;

  uint32_t EncodeSize(size_t length, std::string* output) {
    PutVarint32(output, length);
    return output->size();
  }

  bool DecodeSize(const char** input, size_t* input_length,
                  uint32_t* output_length) {
    auto new_input =
        GetVarint32Ptr(*input, *input + *input_length, output_length);
    if (new_input == nullptr) {
      return false;
    }

    *input_length -= (new_input - *input);
    *input = new_input;
    return true;
  }

  Status ResizeBuffer(std::string* buf, size_t sz) {
    try {
      buf->resize(sz);
    } catch (std::bad_alloc& e) {
      return Status::Corruption(MEMORY_ALLOCATION_ERROR);
    } catch (std::length_error& e) {
      return Status::InvalidArgument();
    }

    return Status::OK();
  }

  Status ParseErrCodeQZ(int err_code) {
    switch (err_code) {
      case QZ_OK:
        return Status::OK();
      case QZ_PARAMS:
        return Status::InvalidArgument();
      case QZ_NOSW_NO_HW:
      case QZ_NOSW_NO_MDRV:
      case QZ_NO_SW_AVAIL:
        return Status::NotFound();
      case QZ_NOSW_NO_INST_ATTACH:
        return Status::Busy();
      case QZ_BUF_ERROR:
      case QZ_NOSW_LOW_MEM:
        return Status::MemoryLimit();
      case QZ_UNSUPPORTED_FMT:
      case QZ_NOSW_UNSUPPORTED_FMT:
        return Status::NotSupported();
      case QZ_DATA_ERROR:
      case QZ_FAIL:
      default:
        return Status::Corruption();
    }
  }

  Status FindSession(QzSession_T** sess) {
    const std::lock_guard<std::mutex> session_lock(session_mutex_);

    const std::thread::id tid = std::this_thread::get_id();
    auto sessions_iter = sessions_.find(tid);
    if (sessions_iter == sessions_.end()) {
      // Allocate a new QATzip session handle
      try {
        *sess = new QzSession_T;
        memset(*sess, 0, sizeof(QzSession_T));
      } catch (std::bad_alloc& e) {
        return Status::Corruption(MEMORY_ALLOCATION_ERROR);
      }

      // Initialize QAT hardware
      int status = qzInit(*sess, options_.sw_backup);
      if (status != QZ_OK && status != QZ_DUPLICATE) {
        Error(logger_, "qzInit() call for session %p returned %d\n", *sess,
              status);
        delete *sess;
        *sess = nullptr;
        return ParseErrCodeQZ(status);
      } else {
        Debug(logger_, "qzInit() call for session %p returned %d\n", *sess,
              status);
      }

      // Get the default parameters
      QzSessionParams_T df_params;
      status = qzGetDefaults(&df_params);
      if (status != QZ_OK) {
        Error(logger_, "qzGetDefaults() call returned %d\n", status);

        // Attempt to teardown the session
        int estatus = qzTeardownSession(*sess);
        if (estatus != QZ_OK) {
          Warn(logger_, "qzTeardownSession() call for session %p returned %d\n",
               *sess, status);
        }

        // Attempt to close the session
        estatus = qzClose(*sess);
        if (estatus != QZ_OK) {
          Warn(logger_, "qzClose() call for session %p returned %d", *sess,
               estatus);
        }

        delete *sess;
        *sess = nullptr;
        return ParseErrCodeQZ(status);
      }

      // Populate the parameter list and try to setup a new session
      QzSessionParamsDeflate_T deflate_params = {};
      QzSessionParamsLZ4_T lz4_params = {};
      if (options_.comp_algorithm == QZ_DEFLATE) {
        deflate_params.common_params.direction = QZ_DIR_BOTH;
        deflate_params.common_params.comp_lvl = options_.comp_lvl;
        deflate_params.common_params.comp_algorithm = options_.comp_algorithm;
        deflate_params.common_params.max_forks = QZ_MAX_FORK_DEFAULT;
        deflate_params.common_params.sw_backup = options_.sw_backup;
        deflate_params.common_params.hw_buff_sz = options_.hw_buff_sz;
        deflate_params.common_params.strm_buff_sz = options_.strm_buff_sz;
        deflate_params.common_params.input_sz_thrshold =
            options_.input_sz_thrshold;
        deflate_params.common_params.req_cnt_thrshold =
            df_params.req_cnt_thrshold;
        deflate_params.common_params.wait_cnt_thrshold =
            options_.wait_cnt_thrshold;
        deflate_params.common_params.polling_mode = options_.polling_mode;
        deflate_params.common_params.is_sensitive_mode =
            options_.is_sensitive_mode;
        deflate_params.huffman_hdr = options_.huffman_hdr;
        deflate_params.data_fmt = options_.data_fmt;
        status = qzSetupSessionDeflate(*sess, &deflate_params);
      } else if (options_.comp_algorithm == QZ_LZ4) {
        lz4_params.common_params.direction = QZ_DIR_BOTH;
        lz4_params.common_params.comp_lvl = options_.comp_lvl;
        lz4_params.common_params.comp_algorithm = options_.comp_algorithm;
        lz4_params.common_params.max_forks = QZ_MAX_FORK_DEFAULT;
        lz4_params.common_params.sw_backup = options_.sw_backup;
        lz4_params.common_params.hw_buff_sz = options_.hw_buff_sz;
        lz4_params.common_params.strm_buff_sz = options_.strm_buff_sz;
        lz4_params.common_params.input_sz_thrshold = options_.input_sz_thrshold;
        lz4_params.common_params.req_cnt_thrshold = df_params.req_cnt_thrshold;
        lz4_params.common_params.wait_cnt_thrshold = options_.wait_cnt_thrshold;
        lz4_params.common_params.polling_mode = options_.polling_mode;
        lz4_params.common_params.is_sensitive_mode = options_.is_sensitive_mode;
        status = qzSetupSessionLZ4(*sess, &lz4_params);
      } else {
        Error(logger_, "Unknown QATzip algorirthm code (%u) requested\n",
              options_.comp_algorithm);
        delete *sess;
        *sess = nullptr;
        return Status::InvalidArgument();
      }

      // Parameter debug logs
      Debug(logger_, "Attempting to setup session %p with huffman_hdr = %u\n",
            *sess, options_.huffman_hdr);
      Debug(logger_, "Attempting to setup session %p with direction = %u\n",
            *sess, QZ_DIR_BOTH);
      Debug(logger_, "Attempting to setup session %p with data_fmt = %u\n",
            *sess, options_.data_fmt);
      Debug(logger_, "Attempting to setup session %p with max_forks = %u\n",
            *sess, QZ_MAX_FORK_DEFAULT);
      Debug(logger_, "Attempting to setup session %p with comp_lvl = %u\n",
            *sess, options_.comp_lvl);
      Debug(logger_,
            "Attempting to setup session %p with comp_alogrithm = %u\n", *sess,
            options_.comp_algorithm);
      Debug(logger_, "Attempting to setup session %p with sw_backup = %u\n",
            *sess, options_.sw_backup);
      Debug(logger_, "Attempting to setup session %p with hw_buff_sz = %u\n",
            *sess, options_.hw_buff_sz);
      Debug(logger_, "Attempting to setup session %p with strm_buff_sz = %u\n",
            *sess, options_.strm_buff_sz);
      Debug(logger_,
            "Attempting to setup session %p with input_sz_thrshold = %u\n",
            *sess, options_.input_sz_thrshold);
      Debug(logger_,
            "Attempting to setup session %p with req_cnt_thrshold = %u\n",
            *sess, df_params.req_cnt_thrshold);
      Debug(logger_,
            "Attempting to setup session %p with wait_cnt_thrshold = %u\n",
            *sess, options_.wait_cnt_thrshold);
      Debug(logger_, "Attempting to setup session %p with polling_mode = %u\n",
            *sess, options_.polling_mode);

      // Check how the setup attempt went
      if (status != QZ_OK) {
        Error(logger_, "QATzip setup call for session %p returned %d\n", *sess,
              status);

        // Attempt to teardown the session
        int estatus = qzTeardownSession(*sess);
        if (estatus != QZ_OK) {
          Warn(logger_, "qzTeardownSession() call for session %p returned %d\n",
               *sess, status);
        }

        // Attempt to close the session
        estatus = qzClose(*sess);
        if (estatus != QZ_OK) {
          Warn(logger_, "qzClose() call for session %p returned %d\n", *sess,
               estatus);
        }

        delete *sess;
        *sess = nullptr;
        return ParseErrCodeQZ(status);
      }

      // Store the new session handle
      sessions_[tid] = *sess;

      Debug(logger_, "QATzip session %p setup complete\n", *sess);
    } else {
      // Use the existing session handle
      *sess = sessions_iter->second;
    }

    return Status::OK();
  }
};

std::unique_ptr<Compressor> NewQATCompressor(void) {
  return std::unique_ptr<Compressor>(new QATCompressor());
}
}  // namespace ROCKSDB_NAMESPACE
