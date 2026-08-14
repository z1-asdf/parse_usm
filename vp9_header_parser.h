#pragma once

#include <cstdint>
#include <ostream>

// ============================================================
// uncompressed_header 解析結果，供 compressed_header 解析使用
// ============================================================
struct VP9FrameContext {
  bool uncompressed_ok =
      false; // uncompressed header 是否完整讀完（沒撞到邊界）
  bool show_existing_frame = false;
  int profile = -1;
  int frame_type = -1; // 0=KEY, 1=NON_KEY
  bool frame_is_intra = false;
  int error_resilient_mode = -1;
  bool intra_only = false;

  bool have_sign_bias = false;
  int ref_frame_sign_bias[4] = {0, 0, 0, 0}; // index 1=LAST,2=GOLDEN,3=ALTREF

  bool have_allow_hp_mv = false;
  int allow_high_precision_mv = 0;

  int interpolation_filter_switchable =
      -1; // 1=switchable, 0=固定, -1=不適用(intra)

  bool lossless = false;

  uint32_t header_size_in_bytes = 0;
  const uint8_t *compressed_header_start = nullptr;
};

void parse_vp9_uncompressed_header(const uint8_t *ptr, const uint8_t *end_ptr,
                                   std::ostream &out, VP9FrameContext &ctx);

void parse_vp9_compressed_header(const VP9FrameContext &ctx,
                                 const uint8_t *enc_end, std::ostream &out);