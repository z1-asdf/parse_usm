#pragma once

#include <cstdint>
#include <map>
#include <string>

// ============================================================
// VP9 標頭解析 context 與標記容器 (Silent 版本)
// ============================================================
struct VP9FrameContext {
  bool uncompressed_ok = false; // uncompressed header 是否完整讀完
  bool show_existing_frame = false;
  int profile = -1;
  int frame_type = -1; // 0=KEY_FRAME, 1=NON_KEY_FRAME
  bool frame_is_intra = false;
  int error_resilient_mode = -1;
  bool intra_only = false;

  bool have_sign_bias = false;
  int ref_frame_sign_bias[4] = {0, 0, 0, 0}; // index 1=LAST, 2=GOLDEN, 3=ALTREF

  bool have_allow_hp_mv = false;
  int allow_high_precision_mv = 0;

  int interpolation_filter_switchable = -1; // 1=switchable, 0=固定, -1=不適用

  bool lossless = false;

  uint32_t header_size_in_bytes = 0;
  const uint8_t *compressed_header_start = nullptr;

  // 儲存解析出來的所有標記與欄位 (key-value)
  std::map<std::string, std::string> uncompressed_tags;
  std::map<std::string, std::string> compressed_tags;
};

// 無 console/stream 輸出的高效靜音解析函式
void parse_vp9_uncompressed_header_silent(const uint8_t *ptr,
                                          const uint8_t *end_ptr,
                                          VP9FrameContext &ctx);

void parse_vp9_compressed_header_silent(const uint8_t *enc_end,
                                        VP9FrameContext &ctx);
