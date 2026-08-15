// ============================================================
// vp9_header_parser_silent.cpp
//
// 靜音版 VP9 uncompressed_header() 與 compressed_header() 解析器。
// 移除所有 std::ostream 輸出開銷，將解析到的欄位與旗標紀錄至
// ctx.uncompressed_tags 與 ctx.compressed_tags Map 中。
// ============================================================

#include "vp9_header_parser_silent.h"

#include <algorithm>
#include <cstdint>
#include <exception>
#include <string>

namespace vp9hdr_silent {

struct BoundaryReached : std::exception {
  const char *what() const noexcept override { return "已到達加密邊界"; }
};

class BitReader {
public:
  BitReader(const uint8_t *begin, const uint8_t *end)
      : begin_(begin), end_(end), bit_pos_(0) {}

  uint32_t f(int n) {
    uint32_t v = 0;
    for (int i = 0; i < n; ++i) {
      size_t byte_index = bit_pos_ >> 3;
      if (begin_ + byte_index >= end_)
        throw BoundaryReached();
      uint8_t byte = begin_[byte_index];
      uint32_t bit = (byte >> (7 - (bit_pos_ & 7))) & 1u;
      v = (v << 1) | bit;
      ++bit_pos_;
    }
    return v;
  }

  int32_t su(int n) {
    int32_t value = static_cast<int32_t>(f(n));
    return f(1) ? -value : value;
  }

  size_t bytes_consumed() const { return (bit_pos_ + 7) >> 3; }

private:
  const uint8_t *begin_;
  const uint8_t *end_;
  size_t bit_pos_;
};

class PaddedBitReader {
public:
  PaddedBitReader(const uint8_t *begin, const uint8_t *header_end,
                  const uint8_t *enc_end)
      : begin_(begin), header_end_(header_end), enc_end_(enc_end), bit_pos_(0) {
  }

  uint32_t f(int n) {
    uint32_t v = 0;
    for (int i = 0; i < n; ++i) {
      size_t byte_index = bit_pos_ >> 3;
      const uint8_t *p = begin_ + byte_index;
      if (p >= enc_end_)
        throw BoundaryReached();
      uint32_t bit = 0;
      if (p < header_end_) {
        uint8_t byte = *p;
        bit = (byte >> (7 - (bit_pos_ & 7))) & 1u;
      }
      v = (v << 1) | bit;
      ++bit_pos_;
    }
    return v;
  }

  size_t bytes_consumed() const { return (bit_pos_ + 7) >> 3; }

private:
  const uint8_t *begin_;
  const uint8_t *header_end_;
  const uint8_t *enc_end_;
  size_t bit_pos_;
};

class BoolDecoder {
public:
  explicit BoolDecoder(PaddedBitReader &r) : br_(r), range_(255) {
    value_ = br_.f(8);
  }

  int read_bool(int p) {
    uint32_t split = 1 + (((range_ - 1) * static_cast<uint32_t>(p)) >> 8);
    int ret;
    if (value_ < split) {
      range_ = split;
      ret = 0;
    } else {
      range_ -= split;
      value_ -= split;
      ret = 1;
    }
    while (range_ < 128) {
      uint32_t new_bit = br_.f(1);
      range_ <<= 1;
      value_ = (value_ << 1) | new_bit;
    }
    return ret;
  }

  uint32_t read_literal(int n) {
    uint32_t x = 0;
    for (int i = 0; i < n; ++i)
      x = (x << 1) | static_cast<uint32_t>(read_bool(128));
    return x;
  }

private:
  PaddedBitReader &br_;
  uint32_t value_;
  uint32_t range_;
};

inline uint32_t decode_term_subexp(BoolDecoder &bd) {
  if (bd.read_literal(1) == 0)
    return bd.read_literal(4);
  if (bd.read_literal(1) == 0)
    return bd.read_literal(4) + 16;
  if (bd.read_literal(1) == 0)
    return bd.read_literal(5) + 32;
  uint32_t v = bd.read_literal(7);
  if (v < 65)
    return v + 64;
  uint32_t bit = bd.read_literal(1);
  return (v << 1) - 1 + bit + 64;
}

inline bool diff_update_prob(BoolDecoder &bd) {
  int update = bd.read_bool(252);
  if (update) {
    decode_term_subexp(bd);
    return true;
  }
  return false;
}

inline bool update_mv_prob(BoolDecoder &bd) {
  int update = bd.read_bool(252);
  if (update) {
    bd.read_literal(7);
    return true;
  }
  return false;
}

} // namespace vp9hdr_silent

void parse_vp9_uncompressed_header_silent(const uint8_t *ptr,
                                          const uint8_t *end_ptr,
                                          VP9FrameContext &ctx) {
  using namespace vp9hdr_silent;
  ctx.uncompressed_tags.clear();

  if (end_ptr <= ptr) {
    ctx.uncompressed_tags["status"] = "EMPTY_DATA";
    return;
  }

  BitReader br(ptr, end_ptr);

  try {
    uint32_t frame_marker = br.f(2);
    ctx.uncompressed_tags["frame_marker"] = std::to_string(frame_marker);

    uint32_t profile_low = br.f(1);
    uint32_t profile_high = br.f(1);
    ctx.profile = static_cast<int>((profile_high << 1) | profile_low);
    ctx.uncompressed_tags["profile"] = std::to_string(ctx.profile);

    if (ctx.profile == 3) {
      uint32_t reserved_zero = br.f(1);
      ctx.uncompressed_tags["reserved_zero"] = std::to_string(reserved_zero);
    }

    uint32_t show_existing_frame = br.f(1);
    ctx.uncompressed_tags["show_existing_frame"] =
        std::to_string(show_existing_frame);
    if (show_existing_frame == 1) {
      uint32_t idx = br.f(3);
      ctx.uncompressed_tags["frame_to_show_map_idx"] = std::to_string(idx);
      ctx.show_existing_frame = true;
      ctx.uncompressed_ok = true;
      ctx.header_size_in_bytes = 0;
      ctx.uncompressed_tags["status"] = "SHOW_EXISTING_FRAME";
      return;
    }

    ctx.frame_type = static_cast<int>(br.f(1));
    bool is_keyframe = (ctx.frame_type == 0);
    ctx.uncompressed_tags["frame_type"] =
        is_keyframe ? "KEY_FRAME" : "NON_KEY_FRAME";

    uint32_t show_frame = br.f(1);
    ctx.uncompressed_tags["show_frame"] = std::to_string(show_frame);

    uint32_t error_resilient = br.f(1);
    ctx.error_resilient_mode = static_cast<int>(error_resilient);
    ctx.uncompressed_tags["error_resilient_mode"] =
        std::to_string(error_resilient);

    if (is_keyframe) {
      ctx.frame_is_intra = true;
      uint32_t sync = br.f(24);
      ctx.uncompressed_tags["frame_sync_code"] = std::to_string(sync);

      int bit_depth = 8;
      if (ctx.profile >= 2) {
        uint32_t t = br.f(1);
        bit_depth = t ? 12 : 10;
      }
      ctx.uncompressed_tags["bit_depth"] = std::to_string(bit_depth);

      uint32_t color_space = br.f(3);
      ctx.uncompressed_tags["color_space"] = std::to_string(color_space);
      if (color_space != 7) {
        uint32_t color_range = br.f(1);
        ctx.uncompressed_tags["color_range"] = std::to_string(color_range);
        if (ctx.profile == 1 || ctx.profile == 3) {
          uint32_t sx = br.f(1), sy = br.f(1);
          ctx.uncompressed_tags["subsampling_x"] = std::to_string(sx);
          ctx.uncompressed_tags["subsampling_y"] = std::to_string(sy);
          br.f(1);
        }
      } else if (ctx.profile == 1 || ctx.profile == 3) {
        br.f(1);
      }

      uint32_t w_m1 = br.f(16), h_m1 = br.f(16);
      ctx.uncompressed_tags["frame_width"] = std::to_string(w_m1 + 1);
      ctx.uncompressed_tags["frame_height"] = std::to_string(h_m1 + 1);

      uint32_t diff = br.f(1);
      ctx.uncompressed_tags["render_and_frame_size_different"] =
          std::to_string(diff);
      if (diff) {
        uint32_t rw = br.f(16), rh = br.f(16);
        ctx.uncompressed_tags["render_width"] = std::to_string(rw + 1);
        ctx.uncompressed_tags["render_height"] = std::to_string(rh + 1);
      }
    } else {
      if (show_frame == 0) {
        uint32_t io = br.f(1);
        ctx.intra_only = (io != 0);
        ctx.uncompressed_tags["intra_only"] = std::to_string(io);
      } else {
        ctx.intra_only = false;
        ctx.uncompressed_tags["intra_only"] = "0";
      }
      ctx.frame_is_intra = ctx.intra_only;

      if (error_resilient == 0) {
        uint32_t rfc = br.f(2);
        ctx.uncompressed_tags["reset_frame_context"] = std::to_string(rfc);
      } else {
        ctx.uncompressed_tags["reset_frame_context"] = "0";
      }

      if (ctx.intra_only) {
        uint32_t sync = br.f(24);
        ctx.uncompressed_tags["frame_sync_code"] = std::to_string(sync);
        if (ctx.profile > 0) {
          if (ctx.profile >= 2) {
            uint32_t t = br.f(1);
            ctx.uncompressed_tags["bit_depth"] = t ? "12" : "10";
          }
          uint32_t color_space = br.f(3);
          ctx.uncompressed_tags["color_space"] = std::to_string(color_space);
          if (color_space != 7) {
            uint32_t color_range = br.f(1);
            ctx.uncompressed_tags["color_range"] = std::to_string(color_range);
            if (ctx.profile == 1 || ctx.profile == 3) {
              br.f(1);
              br.f(1);
              br.f(1);
            }
          } else if (ctx.profile == 1 || ctx.profile == 3) {
            br.f(1);
          }
        }
        uint32_t rff = br.f(8);
        ctx.uncompressed_tags["refresh_frame_flags"] = std::to_string(rff);
        uint32_t w_m1 = br.f(16), h_m1 = br.f(16);
        ctx.uncompressed_tags["frame_width"] = std::to_string(w_m1 + 1);
        ctx.uncompressed_tags["frame_height"] = std::to_string(h_m1 + 1);
        uint32_t diff = br.f(1);
        ctx.uncompressed_tags["render_and_frame_size_different"] =
            std::to_string(diff);
        if (diff) {
          br.f(16);
          br.f(16);
        }
      } else {
        uint32_t rff = br.f(8);
        ctx.uncompressed_tags["refresh_frame_flags"] = std::to_string(rff);
        for (int i = 0; i < 3; ++i) {
          uint32_t ref_idx = br.f(3);
          uint32_t sign_bias = br.f(1);
          ctx.ref_frame_sign_bias[i + 1] = static_cast<int>(sign_bias);
          ctx.uncompressed_tags["ref_frame_idx_" + std::to_string(i)] =
              std::to_string(ref_idx);
          ctx.uncompressed_tags["sign_bias_" + std::to_string(i)] =
              std::to_string(sign_bias);
        }
        ctx.have_sign_bias = true;

        bool found_ref = false;
        for (int i = 0; i < 3; ++i) {
          uint32_t fr = br.f(1);
          if (fr) {
            found_ref = true;
            break;
          }
        }
        if (!found_ref) {
          uint32_t w_m1 = br.f(16), h_m1 = br.f(16);
          ctx.uncompressed_tags["frame_width"] = std::to_string(w_m1 + 1);
          ctx.uncompressed_tags["frame_height"] = std::to_string(h_m1 + 1);
        }
        uint32_t diff = br.f(1);
        ctx.uncompressed_tags["render_and_frame_size_different"] =
            std::to_string(diff);
        if (diff) {
          br.f(16);
          br.f(16);
        }

        uint32_t hp_mv = br.f(1);
        ctx.allow_high_precision_mv = static_cast<int>(hp_mv);
        ctx.have_allow_hp_mv = true;
        ctx.uncompressed_tags["allow_high_precision_mv"] =
            std::to_string(hp_mv);

        uint32_t switchable = br.f(1);
        ctx.interpolation_filter_switchable = switchable ? 1 : 0;
        ctx.uncompressed_tags["is_filter_switchable"] =
            std::to_string(switchable);
        if (!switchable) {
          uint32_t filt = br.f(2);
          static const char *names[4] = {"EIGHTTAP", "EIGHTTAP_SMOOTH",
                                         "EIGHTTAP_SHARP", "BILINEAR"};
          ctx.uncompressed_tags["raw_interpolation_filter"] = names[filt & 3];
        }
      }
    }

    if (error_resilient == 0) {
      uint32_t rfc = br.f(1), fpdm = br.f(1);
      ctx.uncompressed_tags["refresh_frame_context"] = std::to_string(rfc);
      ctx.uncompressed_tags["frame_parallel_decoding_mode"] =
          std::to_string(fpdm);
    }

    uint32_t frame_context_idx = br.f(2);
    ctx.uncompressed_tags["frame_context_idx"] =
        std::to_string(frame_context_idx);

    uint32_t lf_level = br.f(6), lf_sharp = br.f(3);
    ctx.uncompressed_tags["loop_filter_level"] = std::to_string(lf_level);
    ctx.uncompressed_tags["loop_filter_sharpness"] = std::to_string(lf_sharp);

    uint32_t lf_delta_enabled = br.f(1);
    ctx.uncompressed_tags["loop_filter_delta_enabled"] =
        std::to_string(lf_delta_enabled);
    if (lf_delta_enabled) {
      uint32_t lf_delta_update = br.f(1);
      ctx.uncompressed_tags["loop_filter_delta_update"] =
          std::to_string(lf_delta_update);
      if (lf_delta_update) {
        for (int i = 0; i < 4; ++i) {
          if (br.f(1))
            br.su(6);
        }
        for (int i = 0; i < 2; ++i) {
          if (br.f(1))
            br.su(6);
        }
      }
    }

    uint32_t base_q_idx = br.f(8);
    ctx.uncompressed_tags["base_q_idx"] = std::to_string(base_q_idx);

    auto read_delta_q = [&](const char *name) -> int32_t {
      uint32_t coded = br.f(1);
      int32_t v = 0;
      if (coded)
        v = br.su(4);
      ctx.uncompressed_tags[name] = std::to_string(v);
      return v;
    };
    int32_t dq_y_dc = read_delta_q("delta_q_y_dc");
    int32_t dq_uv_dc = read_delta_q("delta_q_uv_dc");
    int32_t dq_uv_ac = read_delta_q("delta_q_uv_ac");
    ctx.lossless =
        (base_q_idx == 0 && dq_y_dc == 0 && dq_uv_dc == 0 && dq_uv_ac == 0);
    ctx.uncompressed_tags["lossless"] = ctx.lossless ? "1" : "0";

    uint32_t seg_enabled = br.f(1);
    ctx.uncompressed_tags["segmentation_enabled"] = std::to_string(seg_enabled);
    if (seg_enabled) {
      uint32_t update_map = br.f(1);
      ctx.uncompressed_tags["segmentation_update_map"] =
          std::to_string(update_map);
      if (update_map) {
        for (int i = 0; i < 7; ++i) {
          if (br.f(1))
            br.f(8);
        }
        uint32_t temporal = br.f(1);
        ctx.uncompressed_tags["segmentation_temporal_update"] =
            std::to_string(temporal);
        for (int i = 0; i < 3; ++i) {
          if (temporal && br.f(1))
            br.f(8);
        }
      }
      uint32_t update_data = br.f(1);
      ctx.uncompressed_tags["segmentation_update_data"] =
          std::to_string(update_data);
      if (update_data) {
        br.f(1);
        static const int bits_for_feature[4] = {8, 6, 2, 0};
        static const bool signed_for_feature[4] = {true, true, false, false};
        for (int seg = 0; seg < 8; ++seg) {
          for (int j = 0; j < 4; ++j) {
            if (br.f(1)) {
              int bits = bits_for_feature[j];
              if (bits > 0)
                br.f(bits);
              if (signed_for_feature[j])
                br.f(1);
            }
          }
        }
      }
    }

    {
      uint32_t inc_cols = 1;
      int guard = 0;
      while (inc_cols && guard < 6) {
        inc_cols = br.f(1);
        if (!inc_cols)
          break;
        ++guard;
      }
      uint32_t inc_rows = br.f(1);
      if (inc_rows)
        br.f(1);
    }

    uint32_t header_size = br.f(16);
    ctx.header_size_in_bytes = header_size;
    ctx.compressed_header_start = ptr + br.bytes_consumed();
    ctx.uncompressed_ok = true;
    ctx.uncompressed_tags["header_size_in_bytes"] = std::to_string(header_size);
    ctx.uncompressed_tags["bytes_consumed"] =
        std::to_string(br.bytes_consumed());
    ctx.uncompressed_tags["status"] = "OK";

  } catch (const vp9hdr_silent::BoundaryReached &) {
    ctx.uncompressed_tags["status"] = "BOUNDARY_REACHED";
    ctx.uncompressed_tags["bytes_consumed"] =
        std::to_string(br.bytes_consumed());
  }
}

void parse_vp9_compressed_header_silent(const uint8_t *enc_end,
                                        VP9FrameContext &ctx) {
  using namespace vp9hdr_silent;
  ctx.compressed_tags.clear();

  if (!ctx.uncompressed_ok) {
    ctx.compressed_tags["status"] = "UNCOMPRESSED_HEADER_INCOMPLETE";
    return;
  }
  if (ctx.show_existing_frame || ctx.header_size_in_bytes == 0) {
    ctx.compressed_tags["status"] = "NO_COMPRESSED_HEADER";
    return;
  }

  const uint8_t *start = ctx.compressed_header_start;
  const uint8_t *header_end = start + ctx.header_size_in_bytes;
  ptrdiff_t avail = enc_end - start;

  if (avail <= 0) {
    ctx.compressed_tags["status"] = "START_BEYOND_ENCRYPTED_BOUNDARY";
    return;
  }

  PaddedBitReader pbr(start, header_end, enc_end);
  BoolDecoder bd(pbr);

  int tx_mode = -1;
  int coef_txsz_reached = -1;
  int coef_updated = 0, coef_total = 0;
  int skip_updated = 0;
  int inter_mode_updated = 0, interp_filter_updated = 0, is_inter_updated = 0;
  int comp_mode_updated = 0, single_ref_updated = 0, comp_ref_updated = 0;
  int y_mode_updated = 0, partition_updated = 0, mv_updated = 0;

  try {
    if (ctx.lossless) {
      tx_mode = 0;
      ctx.compressed_tags["tx_mode"] = "ONLY_4X4";
    } else {
      uint32_t tm = bd.read_literal(2);
      tx_mode = static_cast<int>(tm);
      if (tm == 3) {
        uint32_t sel = bd.read_literal(1);
        if (sel)
          tx_mode = 4;
      }
      static const char *names[5] = {"ONLY_4X4", "ALLOW_8X8", "ALLOW_16X16",
                                     "ALLOW_32X32", "TX_MODE_SELECT"};
      ctx.compressed_tags["tx_mode"] = names[tx_mode];
    }

    if (tx_mode == 4) {
      int updated = 0, total = 0;
      for (int i = 0; i < 2; ++i)
        for (int j = 0; j < 1; ++j) {
          total++;
          if (diff_update_prob(bd))
            updated++;
        }
      for (int i = 0; i < 2; ++i)
        for (int j = 0; j < 2; ++j) {
          total++;
          if (diff_update_prob(bd))
            updated++;
        }
      for (int i = 0; i < 2; ++i)
        for (int j = 0; j < 3; ++j) {
          total++;
          if (diff_update_prob(bd))
            updated++;
        }
      ctx.compressed_tags["tx_mode_probs_updated"] =
          std::to_string(updated) + "/" + std::to_string(total);
    }

    static const int tx_mode_to_max_txsz[5] = {0, 1, 2, 3, 3};
    int max_tx_sz = tx_mode_to_max_txsz[tx_mode];
    for (int txsz = 0; txsz <= max_tx_sz; ++txsz) {
      coef_txsz_reached = txsz;
      uint32_t update_probs = bd.read_literal(1);
      if (update_probs) {
        for (int i = 0; i < 2; ++i)
          for (int j = 0; j < 2; ++j)
            for (int k = 0; k < 6; ++k) {
              int maxL = (k == 0) ? 3 : 6;
              for (int l = 0; l < maxL; ++l)
                for (int m = 0; m < 3; ++m) {
                  coef_total++;
                  if (diff_update_prob(bd))
                    coef_updated++;
                }
            }
      }
    }
    ctx.compressed_tags["coef_probs_updated"] =
        std::to_string(coef_updated) + "/" + std::to_string(coef_total);

    for (int i = 0; i < 3; ++i)
      if (diff_update_prob(bd))
        skip_updated++;
    ctx.compressed_tags["skip_prob_updated"] =
        std::to_string(skip_updated) + "/3";

    if (!ctx.frame_is_intra) {
      for (int i = 0; i < 7; ++i)
        for (int j = 0; j < 3; ++j)
          if (diff_update_prob(bd))
            inter_mode_updated++;
      ctx.compressed_tags["inter_mode_probs_updated"] =
          std::to_string(inter_mode_updated) + "/21";

      if (ctx.interpolation_filter_switchable == 1) {
        for (int i = 0; i < 4; ++i)
          for (int j = 0; j < 2; ++j)
            if (diff_update_prob(bd))
              interp_filter_updated++;
        ctx.compressed_tags["interp_filter_probs_updated"] =
            std::to_string(interp_filter_updated) + "/8";
      }

      for (int i = 0; i < 4; ++i)
        if (diff_update_prob(bd))
          is_inter_updated++;
      ctx.compressed_tags["is_inter_prob_updated"] =
          std::to_string(is_inter_updated) + "/4";

      int reference_mode = 0;
      bool compound_allowed = false;
      if (ctx.have_sign_bias) {
        for (int i = 1; i <= 2; ++i)
          if (ctx.ref_frame_sign_bias[i + 1] != ctx.ref_frame_sign_bias[1])
            compound_allowed = true;
      }
      if (compound_allowed) {
        uint32_t non_single = bd.read_literal(1);
        if (!non_single) {
          reference_mode = 0;
        } else {
          uint32_t sel = bd.read_literal(1);
          reference_mode = sel ? 2 : 1;
        }
      }
      static const char *ref_mode_names[3] = {
          "SINGLE_REFERENCE", "COMPOUND_REFERENCE", "REFERENCE_MODE_SELECT"};
      ctx.compressed_tags["reference_mode"] = ref_mode_names[reference_mode];

      if (reference_mode == 2) {
        for (int i = 0; i < 5; ++i)
          if (diff_update_prob(bd))
            comp_mode_updated++;
        ctx.compressed_tags["comp_mode_prob_updated"] =
            std::to_string(comp_mode_updated) + "/5";
      }
      if (reference_mode != 1) {
        for (int i = 0; i < 5; ++i) {
          if (diff_update_prob(bd))
            single_ref_updated++;
          if (diff_update_prob(bd))
            single_ref_updated++;
        }
        ctx.compressed_tags["single_ref_prob_updated"] =
            std::to_string(single_ref_updated) + "/10";
      }
      if (reference_mode != 0) {
        for (int i = 0; i < 5; ++i)
          if (diff_update_prob(bd))
            comp_ref_updated++;
        ctx.compressed_tags["comp_ref_prob_updated"] =
            std::to_string(comp_ref_updated) + "/5";
      }

      for (int i = 0; i < 4; ++i)
        for (int j = 0; j < 9; ++j)
          if (diff_update_prob(bd))
            y_mode_updated++;
      ctx.compressed_tags["y_mode_probs_updated"] =
          std::to_string(y_mode_updated) + "/36";

      for (int i = 0; i < 16; ++i)
        for (int j = 0; j < 3; ++j)
          if (diff_update_prob(bd))
            partition_updated++;
      ctx.compressed_tags["partition_probs_updated"] =
          std::to_string(partition_updated) + "/48";

      int mv_total = 0;
      for (int j = 0; j < 3; ++j) {
        mv_total++;
        if (update_mv_prob(bd))
          mv_updated++;
      }
      for (int i = 0; i < 2; ++i) {
        mv_total++;
        if (update_mv_prob(bd))
          mv_updated++;
        for (int j = 0; j < 10; ++j) {
          mv_total++;
          if (update_mv_prob(bd))
            mv_updated++;
        }
        mv_total++;
        if (update_mv_prob(bd))
          mv_updated++;
        for (int j = 0; j < 10; ++j) {
          mv_total++;
          if (update_mv_prob(bd))
            mv_updated++;
        }
      }
      for (int i = 0; i < 2; ++i) {
        for (int j = 0; j < 2; ++j)
          for (int k = 0; k < 3; ++k) {
            mv_total++;
            if (update_mv_prob(bd))
              mv_updated++;
          }
        for (int k = 0; k < 3; ++k) {
          mv_total++;
          if (update_mv_prob(bd))
            mv_updated++;
        }
      }
      if (ctx.have_allow_hp_mv && ctx.allow_high_precision_mv) {
        for (int i = 0; i < 2; ++i) {
          mv_total++;
          if (update_mv_prob(bd))
            mv_updated++;
          mv_total++;
          if (update_mv_prob(bd))
            mv_updated++;
        }
      }
      ctx.compressed_tags["mv_probs_updated"] =
          std::to_string(mv_updated) + "/" + std::to_string(mv_total);
    }

    ctx.compressed_tags["bytes_consumed"] =
        std::to_string(pbr.bytes_consumed());
    ctx.compressed_tags["status"] = "OK";

  } catch (const vp9hdr_silent::BoundaryReached &) {
    ctx.compressed_tags["status"] = "BOUNDARY_REACHED";
    ctx.compressed_tags["bytes_consumed"] =
        std::to_string(pbr.bytes_consumed());
    if (coef_txsz_reached >= 0) {
      ctx.compressed_tags["coef_txsz_reached"] =
          std::to_string(coef_txsz_reached);
    }
  }
}
