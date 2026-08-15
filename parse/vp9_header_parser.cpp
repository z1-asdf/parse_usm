// ============================================================
// vp9_header_parser.cpp
//
// 解析 VP9 uncompressed_header() 與 compressed_header()（VP9 spec §6.2 / §6.3），
// 並且知道「USM 加密邊界」在哪裡：一旦下一個要讀的 bit 會踩進加密區，
// 就停止解析，並列出「規格上接下來理應還有哪些欄位、可能的數值範圍」。
//
// 使用方式：
//   VP9FrameContext ctx;
//   parse_vp9_uncompressed_header(vp9_start, enc_boundary, std::cout, ctx);
//   if (ctx.uncompressed_ok)
//       parse_vp9_compressed_header(ctx, enc_boundary, std::cout);
//
// enc_boundary 的算法：
//   一般 chunk : vp9_start + (0x40 - 12)   (= vp9_start + 52)
//   第一個 chunk: vp9_start + (0x40 - 44)  (= vp9_start + 20)
//   packet 總長 < 0x240(576) 時完全沒加密 -> enc_boundary = 資料結尾
//
// 【關於 compressed_header 的精確度，請先讀這段】
// VP9 compressed_header 幾乎全部用 diff_update_prob() 這個「機率增量更新」語法
// 編碼。這個語法的位元消耗量（讀幾個bit、要不要renormalize）完全不依賴任何
// 「預設機率表」的實際數值 —— 預設值只有在算「更新後的最終機率」時才用得到。
// VP9 完整的預設機率表（尤其 coef_probs）有上千個數字，若不是直接從
// libvpx/spec Annex 複製，手動輸入極易出錯又不易察覺。
//
// 因此這支程式對 compressed_header 做的事：
//   1. 完整、逐位元「正確」地走完整個語法結構（bit 消耗量是對的）
//   2. 精準統計「這個群組裡有幾個機率被標記為更新」
//   3. 精準判斷、回報「有沒有撞到加密邊界」以及撞在哪個階段
//   4. 對於被更新的機率，只標註「已更新」，不假裝給你一個可能算錯的最終數值
//      （那需要真正的預設表）
// ============================================================

#include <algorithm>
#include <cstdint>
#include <exception>
#include <ostream>
#include <string>

#include "vp9_header_parser.h"

namespace vp9hdr {

struct BoundaryReached : std::exception {
  const char *what() const noexcept override {
    return "已到達加密邊界，之後的資料不可信";
  }
};

// ---------------- uncompressed_header 用的 bit reader ----------------
// 邊界固定：一旦下一個 byte >= end_，直接視為踩進加密區，丟例外。
class BitReader {
public:
  BitReader(const uint8_t *begin, const uint8_t *end)
      : begin_(begin), end_(end), bit_pos_(0) {}

  uint32_t f(int n) {
    uint32_t v = 0;
    for (int i = 0; i < n; ++i) {
      size_t byte_index = bit_pos_ >> 3;
      if (begin_ + byte_index >= end_) throw BoundaryReached();
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

// ---------------- compressed_header 用的 bit reader ----------------
// 有兩個邊界：
//   header_end_ : spec 上 header_size_in_bytes 的自然結尾。超過它但還沒到
//                 加密邊界時，依 spec 規定補 0（這是正常情況，不是錯誤）。
//   enc_end_    : 加密邊界。一旦踩到，代表 header 被硬生生切斷在加密區裡，丟例外。
class PaddedBitReader {
public:
  PaddedBitReader(const uint8_t *begin, const uint8_t *header_end,
                   const uint8_t *enc_end)
      : begin_(begin), header_end_(header_end), enc_end_(enc_end), bit_pos_(0) {}

  uint32_t f(int n) {
    uint32_t v = 0;
    for (int i = 0; i < n; ++i) {
      size_t byte_index = bit_pos_ >> 3;
      const uint8_t *p = begin_ + byte_index;
      if (p >= enc_end_) throw BoundaryReached();
      uint32_t bit = 0;
      if (p < header_end_) {
        uint8_t byte = *p;
        bit = (byte >> (7 - (bit_pos_ & 7))) & 1u;
      }
      // else: 超過 header_size_in_bytes 但還沒到加密邊界 -> 補0 (spec行為，非錯誤)
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

// VP9 boolean (range) decoder，spec §9.2
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
      uint32_t new_bit = br_.f(1); // 可能丟出 BoundaryReached
      range_ <<= 1;
      value_ = (value_ << 1) | new_bit;
    }
    return ret;
  }

  uint32_t read_literal(int n) {
    uint32_t x = 0;
    for (int i = 0; i < n; ++i) x = (x << 1) | static_cast<uint32_t>(read_bool(128));
    return x;
  }

private:
  PaddedBitReader &br_;
  uint32_t value_;
  uint32_t range_;
};

// decode_term_subexp：只用來正確消耗位元，回傳值本身對「最終機率」沒有
// 意義（那需要搭配預設表 inv_remap_prob），這裡只回傳原始 delta code。
inline uint32_t decode_term_subexp(BoolDecoder &bd) {
  if (bd.read_literal(1) == 0) return bd.read_literal(4);
  if (bd.read_literal(1) == 0) return bd.read_literal(4) + 16;
  if (bd.read_literal(1) == 0) return bd.read_literal(5) + 32;
  uint32_t v = bd.read_literal(7);
  if (v < 65) return v + 64;
  uint32_t bit = bd.read_literal(1);
  return (v << 1) - 1 + bit + 64;
}

// diff_update_prob：回傳這個機率「有沒有被更新」，位元消耗量保證正確。
inline bool diff_update_prob(BoolDecoder &bd) {
  int update = bd.read_bool(252);
  if (update) {
    decode_term_subexp(bd); // 消耗掉 delta 的 bits，數值本身不使用
    return true;
  }
  return false;
}

// mv 機率專用的更新語法（比 diff_update_prob 簡單，7-bit literal 直接當新值）
inline bool update_mv_prob(BoolDecoder &bd) {
  int update = bd.read_bool(252);
  if (update) {
    bd.read_literal(7);
    return true;
  }
  return false;
}

inline void print_keyframe_branch(std::ostream &out) {
  out << "  [KEY_FRAME 分支的完整規格，供對照]\n"
         "  - frame_sync_code: 24 bits，固定值 0x498342\n"
         "  - color_config(): bit_depth/color_space(3bit,0~7)/color_range(1bit)/"
         "subsampling(視profile而定)\n"
         "  - frame_size(): width_minus_1/height_minus_1 各16 bits\n"
         "  - render_size(): 1 bit旗標，若=1再讀2個16 bits\n";
}
inline void print_interframe_branch(std::ostream &out, int show_frame_known) {
  out << "  [NON_KEY_FRAME 分支的完整規格，供對照]\n";
  if (show_frame_known == 0)
    out << "  - intra_only: 1 bit\n";
  else if (show_frame_known == 1)
    out << "  - intra_only: 隱含=0\n";
  else
    out << "  - intra_only: 視 show_frame 而定\n";
  out << "  - reset_frame_context: 視 error_resilient_mode 而定, 0 或 2 bits(0~3)\n"
         "  - intra_only==1: frame_sync_code+color_config+refresh_frame_flags(8bit)"
         "+frame_size+render_size\n"
         "  - intra_only==0: refresh_frame_flags(8bit,0~255) + 3組ref_frame_idx"
         "(3bit,0~7)+sign_bias(1bit) + frame_size_with_refs + "
         "allow_high_precision_mv(1bit) + interpolation_filter(1或3bit)\n";
}
inline void print_common_late_stages(std::ostream &out) {
  out << "  [不分key/inter，之後共同的部分]\n"
         "  - refresh_frame_context/frame_parallel_decoding_mode: 各0或1 bit\n"
         "  - frame_context_idx: 2 bits, 0~3\n"
         "  - loop_filter_params(): level(6bit,0~63)+sharpness(3bit,0~7)+"
         "deltas(視旗標,最多4+2組 su(6))\n"
         "  - quantization_params(): base_q_idx(8bit,0~255)+3組條件性 su(4)\n"
         "  - segmentation_params(): 最複雜，視旗標可能有7個tree_prob+3個pred_prob+"
         "8*4個feature\n"
         "  - tile_info(): tile_cols_log2 / tile_rows_log2，各由1-bit旗標決定\n"
         "  - header_size_in_bytes: 16 bits, 0~65535 -> compressed header 長度\n";
}

} // namespace vp9hdr

// ============================================================
// parse_vp9_uncompressed_header
// ============================================================
void parse_vp9_uncompressed_header(const uint8_t *ptr, const uint8_t *end_ptr,
                                    std::ostream &out, VP9FrameContext &ctx) {
  using namespace vp9hdr;

  if (end_ptr <= ptr) {
    out << "[VP9] end_ptr <= ptr，沒有任何明文資料可讀。\n";
    return;
  }

  BitReader br(ptr, end_ptr);
  bool have_frame_type = false, have_branch = false;
  int show_frame = -1, error_resilient = -1;
  bool reached_common_late = false;

  out << "=== VP9 uncompressed_header 解析 (可用明文長度: "
      << static_cast<size_t>(end_ptr - ptr) << " bytes) ===\n";

  try {
    uint32_t frame_marker = br.f(2);
    out << "frame_marker = " << frame_marker << " (應為 0b10)\n";

    uint32_t profile_low = br.f(1);
    uint32_t profile_high = br.f(1);
    ctx.profile = static_cast<int>((profile_high << 1) | profile_low);
    out << "profile = " << ctx.profile << " (0~3)\n";

    if (ctx.profile == 3) {
      uint32_t reserved_zero = br.f(1);
      out << "reserved_zero (profile==3) = " << reserved_zero << "\n";
    }

    uint32_t show_existing_frame = br.f(1);
    out << "show_existing_frame = " << show_existing_frame << "\n";
    if (show_existing_frame == 1) {
      uint32_t idx = br.f(3);
      out << "frame_to_show_map_idx = " << idx << " (0~7)\n";
      ctx.show_existing_frame = true;
      ctx.uncompressed_ok = true; // 這個 frame 沒有 compressed header
      ctx.header_size_in_bytes = 0;
      out << "(show_existing_frame==1，此 frame 沒有其他 header 內容)\n";
      return;
    }

    ctx.frame_type = static_cast<int>(br.f(1));
    have_frame_type = true;
    bool is_keyframe = (ctx.frame_type == 0);
    out << "frame_type = " << ctx.frame_type << " (0=KEY_FRAME, 1=NON_KEY_FRAME)\n";

    show_frame = static_cast<int>(br.f(1));
    out << "show_frame = " << show_frame << "\n";

    error_resilient = static_cast<int>(br.f(1));
    ctx.error_resilient_mode = error_resilient;
    out << "error_resilient_mode = " << error_resilient << "\n";
    have_branch = true;

    if (is_keyframe) {
      ctx.frame_is_intra = true;
      uint32_t sync = br.f(24);
      out << "frame_sync_code = 0x" << std::hex << sync << std::dec
          << " (應為 0x498342)\n";

      int bit_depth = 8;
      if (ctx.profile >= 2) {
        uint32_t t = br.f(1);
        bit_depth = t ? 12 : 10;
        out << "ten_or_twelve_bit = " << t << " -> BitDepth=" << bit_depth << "\n";
      } else {
        out << "BitDepth = 8 (隱含)\n";
      }
      uint32_t color_space = br.f(3);
      out << "color_space = " << color_space << " (0~7)\n";
      if (color_space != 7) {
        uint32_t color_range = br.f(1);
        out << "color_range = " << color_range << "\n";
        if (ctx.profile == 1 || ctx.profile == 3) {
          uint32_t sx = br.f(1), sy = br.f(1);
          out << "subsampling_x=" << sx << ", subsampling_y=" << sy << "\n";
          br.f(1); // reserved_zero
        }
      } else if (ctx.profile == 1 || ctx.profile == 3) {
        br.f(1); // reserved_zero
      }

      uint32_t w_m1 = br.f(16), h_m1 = br.f(16);
      out << "frame_width = " << (w_m1 + 1) << ", frame_height = " << (h_m1 + 1) << "\n";

      uint32_t diff = br.f(1);
      out << "render_and_frame_size_different = " << diff << "\n";
      if (diff) {
        uint32_t rw = br.f(16), rh = br.f(16);
        out << "render_width = " << (rw + 1) << ", render_height = " << (rh + 1) << "\n";
      }
    } else {
      if (show_frame == 0) {
        uint32_t io = br.f(1);
        ctx.intra_only = (io != 0);
        out << "intra_only = " << io << "\n";
      } else {
        ctx.intra_only = false;
        out << "intra_only = 0 (隱含)\n";
      }
      ctx.frame_is_intra = ctx.intra_only;

      if (error_resilient == 0) {
        uint32_t rfc = br.f(2);
        out << "reset_frame_context = " << rfc << " (0~3)\n";
      } else {
        out << "reset_frame_context = 0 (隱含)\n";
      }

      if (ctx.intra_only) {
        uint32_t sync = br.f(24);
        out << "frame_sync_code = 0x" << std::hex << sync << std::dec << "\n";
        if (ctx.profile > 0) {
          if (ctx.profile >= 2) {
            uint32_t t = br.f(1);
            out << "ten_or_twelve_bit = " << t << "\n";
          }
          uint32_t color_space = br.f(3);
          out << "color_space = " << color_space << "\n";
          if (color_space != 7) {
            uint32_t color_range = br.f(1);
            out << "color_range = " << color_range << "\n";
            if (ctx.profile == 1 || ctx.profile == 3) {
              br.f(1); br.f(1); br.f(1);
              out << "subsampling_x/y + reserved_zero 已讀\n";
            }
          } else if (ctx.profile == 1 || ctx.profile == 3) {
            br.f(1);
          }
        } else {
          out << "color_space=BT601,subsampling=1,1,BitDepth=8 (隱含)\n";
        }
        uint32_t rff = br.f(8);
        out << "refresh_frame_flags = 0x" << std::hex << rff << std::dec << "\n";
        uint32_t w_m1 = br.f(16), h_m1 = br.f(16);
        out << "frame_width=" << (w_m1 + 1) << ", frame_height=" << (h_m1 + 1) << "\n";
        uint32_t diff = br.f(1);
        out << "render_and_frame_size_different=" << diff << "\n";
        if (diff) { br.f(16); br.f(16); out << "render_size 已讀\n"; }
      } else {
        uint32_t rff = br.f(8);
        out << "refresh_frame_flags = 0x" << std::hex << rff << std::dec << "\n";
        for (int i = 0; i < 3; ++i) {
          uint32_t ref_idx = br.f(3);
          uint32_t sign_bias = br.f(1);
          ctx.ref_frame_sign_bias[i + 1] = static_cast<int>(sign_bias);
          out << "ref_frame_idx[" << i << "]=" << ref_idx
              << ", sign_bias=" << sign_bias << "\n";
        }
        ctx.have_sign_bias = true;

        bool found_ref = false;
        for (int i = 0; i < 3; ++i) {
          uint32_t fr = br.f(1);
          out << "found_ref[" << i << "] = " << fr << "\n";
          if (fr) { found_ref = true; break; }
        }
        if (!found_ref) {
          uint32_t w_m1 = br.f(16), h_m1 = br.f(16);
          out << "frame_width=" << (w_m1 + 1) << ", frame_height=" << (h_m1 + 1) << "\n";
        } else {
          out << "(沿用參考幀尺寸)\n";
        }
        uint32_t diff = br.f(1);
        out << "render_and_frame_size_different=" << diff << "\n";
        if (diff) { br.f(16); br.f(16); out << "render_size 已讀\n"; }

        uint32_t hp_mv = br.f(1);
        ctx.allow_high_precision_mv = static_cast<int>(hp_mv);
        ctx.have_allow_hp_mv = true;
        out << "allow_high_precision_mv = " << hp_mv << "\n";

        uint32_t switchable = br.f(1);
        ctx.interpolation_filter_switchable = switchable ? 1 : 0;
        out << "is_filter_switchable = " << switchable << "\n";
        if (!switchable) {
          uint32_t filt = br.f(2);
          static const char *names[4] = {"EIGHTTAP", "EIGHTTAP_SMOOTH",
                                          "EIGHTTAP_SHARP", "BILINEAR"};
          out << "raw_interpolation_filter = " << filt << " (" << names[filt & 3]
              << ")\n";
        }
      }
    }

    reached_common_late = true;

    if (error_resilient == 0) {
      uint32_t rfc = br.f(1), fpdm = br.f(1);
      out << "refresh_frame_context=" << rfc
          << ", frame_parallel_decoding_mode=" << fpdm << "\n";
    } else {
      out << "refresh_frame_context=0, frame_parallel_decoding_mode=1 (隱含)\n";
    }

    uint32_t frame_context_idx = br.f(2);
    out << "frame_context_idx = " << frame_context_idx << " (0~3)\n";

    uint32_t lf_level = br.f(6), lf_sharp = br.f(3);
    out << "loop_filter_level=" << lf_level << ", loop_filter_sharpness=" << lf_sharp << "\n";
    uint32_t lf_delta_enabled = br.f(1);
    out << "loop_filter_delta_enabled=" << lf_delta_enabled << "\n";
    if (lf_delta_enabled) {
      uint32_t lf_delta_update = br.f(1);
      out << "loop_filter_delta_update=" << lf_delta_update << "\n";
      if (lf_delta_update) {
        for (int i = 0; i < 4; ++i) { if (br.f(1)) br.su(6); }
        for (int i = 0; i < 2; ++i) { if (br.f(1)) br.su(6); }
        out << "loop_filter ref/mode deltas 已讀\n";
      }
    }

    uint32_t base_q_idx = br.f(8);
    out << "base_q_idx = " << base_q_idx << " (0~255)\n";
    auto read_delta_q = [&](const char *name) -> int32_t {
      uint32_t coded = br.f(1);
      int32_t v = 0;
      if (coded) v = br.su(4);
      out << name << " = " << v << "\n";
      return v;
    };
    int32_t dq_y_dc = read_delta_q("delta_q_y_dc");
    int32_t dq_uv_dc = read_delta_q("delta_q_uv_dc");
    int32_t dq_uv_ac = read_delta_q("delta_q_uv_ac");
    ctx.lossless = (base_q_idx == 0 && dq_y_dc == 0 && dq_uv_dc == 0 && dq_uv_ac == 0);
    out << "Lossless = " << (ctx.lossless ? 1 : 0) << "\n";

    uint32_t seg_enabled = br.f(1);
    out << "segmentation_enabled = " << seg_enabled << "\n";
    if (seg_enabled) {
      uint32_t update_map = br.f(1);
      out << "segmentation_update_map = " << update_map << "\n";
      if (update_map) {
        for (int i = 0; i < 7; ++i) { if (br.f(1)) br.f(8); }
        uint32_t temporal = br.f(1);
        out << "segmentation_temporal_update = " << temporal << "\n";
        for (int i = 0; i < 3; ++i) { if (temporal && br.f(1)) br.f(8); }
      }
      uint32_t update_data = br.f(1);
      out << "segmentation_update_data = " << update_data << "\n";
      if (update_data) {
        br.f(1); // abs_or_delta_update
        static const int bits_for_feature[4] = {8, 6, 2, 0};
        static const bool signed_for_feature[4] = {true, true, false, false};
        for (int seg = 0; seg < 8; ++seg) {
          for (int j = 0; j < 4; ++j) {
            if (br.f(1)) {
              int bits = bits_for_feature[j];
              if (bits > 0) br.f(bits);
              if (signed_for_feature[j]) br.f(1);
            }
          }
        }
        out << "segmentation feature data 已讀\n";
      }
    }

    {
      uint32_t inc_cols = 1;
      int guard = 0;
      while (inc_cols && guard < 6) {
        inc_cols = br.f(1);
        if (!inc_cols) break;
        ++guard;
      }
      uint32_t inc_rows = br.f(1);
      if (inc_rows) br.f(1);
      out << "tile_info 已讀\n";
    }

    uint32_t header_size = br.f(16);
    ctx.header_size_in_bytes = header_size;
    ctx.compressed_header_start = ptr + br.bytes_consumed();
    ctx.uncompressed_ok = true;
    out << "header_size_in_bytes = " << header_size
        << " -> compressed header 位於 byte offset " << br.bytes_consumed()
        << " ~ " << (br.bytes_consumed() + header_size) << "\n";
    out << "=== uncompressed_header 解析完成，共消耗 " << br.bytes_consumed()
        << " bytes ===\n";

  } catch (const vp9hdr::BoundaryReached &) {
    out << "\n[!] 已到達 end_ptr (加密邊界)，尚未解析完整個 uncompressed_header。\n";
    out << "    已成功讀取 " << br.bytes_consumed() << " bytes\n";
    out << "    以下是規格上「理應還有但已無法確認」的欄位：\n\n";

    if (!have_frame_type) {
      out << "  frame_type 尚未讀到，之後走向完全未知：\n";
      vp9hdr::print_keyframe_branch(out);
      vp9hdr::print_interframe_branch(out, -1);
      vp9hdr::print_common_late_stages(out);
      return;
    }
    if (!have_branch) {
      out << "  show_frame / error_resilient_mode 尚未讀到\n";
    }
    if (ctx.frame_type == 0) {
      vp9hdr::print_keyframe_branch(out);
    } else {
      vp9hdr::print_interframe_branch(out, -1);
    }
    if (!reached_common_late)
      out << "\n  (上面的分支欄位可能只讀了一部分)\n\n";
    vp9hdr::print_common_late_stages(out);
  }
}

// ============================================================
// parse_vp9_compressed_header
// ============================================================
void parse_vp9_compressed_header(const VP9FrameContext &ctx, const uint8_t *enc_end,
                                  std::ostream &out) {
  using namespace vp9hdr;

  if (!ctx.uncompressed_ok) {
    out << "[VP9] uncompressed header 未完整解析，無法定位 compressed header，略過。\n";
    return;
  }
  if (ctx.show_existing_frame || ctx.header_size_in_bytes == 0) {
    out << "[VP9] 此 frame 沒有 compressed header。\n";
    return;
  }

  const uint8_t *start = ctx.compressed_header_start;
  const uint8_t *header_end = start + ctx.header_size_in_bytes;
  ptrdiff_t avail = enc_end - start;

  out << "=== VP9 compressed_header 解析 (spec長度 " << ctx.header_size_in_bytes
      << " bytes, 加密邊界前可用 " << std::max<ptrdiff_t>(0, avail) << " bytes) ===\n";

  if (avail <= 0) {
    out << "[!] compressed header 起點已在加密邊界(或之後)，完全無法解析。\n"
           "    (代表整段 compressed_header + 之後的 tile data 都已加密)\n";
    return;
  }

  PaddedBitReader pbr(start, header_end, enc_end);
  BoolDecoder bd(pbr);

  // 記錄解析進度，供中斷時回報用
  std::string stage = "tx_mode";
  int tx_mode = -1;
  int coef_txsz_reached = -1;
  int coef_updated = 0, coef_total = 0;
  int skip_updated = 0;
  int inter_mode_updated = 0, interp_filter_updated = 0, is_inter_updated = 0;
  int comp_mode_updated = 0, single_ref_updated = 0, comp_ref_updated = 0;
  int y_mode_updated = 0, partition_updated = 0, mv_updated = 0;
  bool reached_skip = false, reached_inter_section = false;

  try {
    // ---- read_tx_mode ----
    if (ctx.lossless) {
      tx_mode = 0; // ONLY_4X4
      out << "tx_mode = ONLY_4X4 (lossless隱含)\n";
    } else {
      uint32_t tm = bd.read_literal(2);
      tx_mode = static_cast<int>(tm);
      if (tm == 3 /*ALLOW_32X32*/) {
        uint32_t sel = bd.read_literal(1);
        if (sel) tx_mode = 4; // TX_MODE_SELECT
      }
      static const char *names[5] = {"ONLY_4X4", "ALLOW_8X8", "ALLOW_16X16",
                                      "ALLOW_32X32", "TX_MODE_SELECT"};
      out << "tx_mode = " << names[tx_mode] << "\n";
    }

    // ---- tx_mode_probs (只有 TX_MODE_SELECT 才有) ----
    if (tx_mode == 4) {
      stage = "tx_mode_probs";
      int updated = 0, total = 0;
      for (int i = 0; i < 2; ++i) for (int j = 0; j < 1; ++j) { total++; if (diff_update_prob(bd)) updated++; }
      for (int i = 0; i < 2; ++i) for (int j = 0; j < 2; ++j) { total++; if (diff_update_prob(bd)) updated++; }
      for (int i = 0; i < 2; ++i) for (int j = 0; j < 3; ++j) { total++; if (diff_update_prob(bd)) updated++; }
      out << "tx_mode_probs: " << updated << "/" << total << " 個機率被更新\n";
    }

    // ---- read_coef_probs ----
    stage = "coef_probs";
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
                  if (diff_update_prob(bd)) coef_updated++;
                }
            }
      }
      out << "coef_probs[txSz=" << txsz << "]: update_probs=" << update_probs
          << ", 累計 " << coef_updated << "/" << coef_total << " 個機率被更新\n";
    }

    // ---- read_skip_prob ----
    stage = "skip_prob";
    for (int i = 0; i < 3; ++i) if (diff_update_prob(bd)) skip_updated++;
    reached_skip = true;
    out << "skip_prob: " << skip_updated << "/3 個機率被更新\n";

    if (!ctx.frame_is_intra) {
      reached_inter_section = true;

      stage = "inter_mode_probs";
      for (int i = 0; i < 7; ++i)
        for (int j = 0; j < 3; ++j)
          if (diff_update_prob(bd)) inter_mode_updated++;
      out << "inter_mode_probs: " << inter_mode_updated << "/21 個機率被更新\n";

      if (ctx.interpolation_filter_switchable == 1) {
        stage = "interp_filter_probs";
        for (int i = 0; i < 4; ++i)
          for (int j = 0; j < 2; ++j)
            if (diff_update_prob(bd)) interp_filter_updated++;
        out << "interp_filter_probs: " << interp_filter_updated << "/8 個機率被更新\n";
      }

      stage = "is_inter_probs";
      for (int i = 0; i < 4; ++i) if (diff_update_prob(bd)) is_inter_updated++;
      out << "is_inter_prob: " << is_inter_updated << "/4 個機率被更新\n";

      // ---- frame_reference_mode ----
      stage = "frame_reference_mode";
      int reference_mode = 0; // 0=SINGLE, 1=COMPOUND, 2=SELECT
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
      static const char *ref_mode_names[3] = {"SINGLE_REFERENCE", "COMPOUND_REFERENCE",
                                                "REFERENCE_MODE_SELECT"};
      out << "reference_mode = " << ref_mode_names[reference_mode] << "\n";

      stage = "frame_reference_mode_probs";
      if (reference_mode == 2) {
        for (int i = 0; i < 5; ++i) if (diff_update_prob(bd)) comp_mode_updated++;
        out << "comp_mode_prob: " << comp_mode_updated << "/5 個機率被更新\n";
      }
      if (reference_mode != 1) {
        for (int i = 0; i < 5; ++i) {
          if (diff_update_prob(bd)) single_ref_updated++;
          if (diff_update_prob(bd)) single_ref_updated++;
        }
        out << "single_ref_prob: " << single_ref_updated << "/10 個機率被更新\n";
      }
      if (reference_mode != 0) {
        for (int i = 0; i < 5; ++i) if (diff_update_prob(bd)) comp_ref_updated++;
        out << "comp_ref_prob: " << comp_ref_updated << "/5 個機率被更新\n";
      }

      stage = "y_mode_probs";
      for (int i = 0; i < 4; ++i)
        for (int j = 0; j < 9; ++j)
          if (diff_update_prob(bd)) y_mode_updated++;
      out << "y_mode_probs: " << y_mode_updated << "/36 個機率被更新\n";

      stage = "partition_probs";
      for (int i = 0; i < 16; ++i)
        for (int j = 0; j < 3; ++j)
          if (diff_update_prob(bd)) partition_updated++;
      out << "partition_probs: " << partition_updated << "/48 個機率被更新\n";

      stage = "mv_probs";
      int mv_total = 0;
      for (int j = 0; j < 3; ++j) { mv_total++; if (update_mv_prob(bd)) mv_updated++; }
      for (int i = 0; i < 2; ++i) {
        mv_total++; if (update_mv_prob(bd)) mv_updated++;
        for (int j = 0; j < 10; ++j) { mv_total++; if (update_mv_prob(bd)) mv_updated++; }
        mv_total++; if (update_mv_prob(bd)) mv_updated++;
        for (int j = 0; j < 10; ++j) { mv_total++; if (update_mv_prob(bd)) mv_updated++; }
      }
      for (int i = 0; i < 2; ++i) {
        for (int j = 0; j < 2; ++j)
          for (int k = 0; k < 3; ++k) { mv_total++; if (update_mv_prob(bd)) mv_updated++; }
        for (int k = 0; k < 3; ++k) { mv_total++; if (update_mv_prob(bd)) mv_updated++; }
      }
      if (ctx.have_allow_hp_mv && ctx.allow_high_precision_mv) {
        for (int i = 0; i < 2; ++i) {
          mv_total++; if (update_mv_prob(bd)) mv_updated++;
          mv_total++; if (update_mv_prob(bd)) mv_updated++;
        }
      }
      out << "mv_probs: " << mv_updated << "/" << mv_total << " 個機率被更新\n";
    }

    out << "=== compressed_header 解析完成，共消耗 " << pbr.bytes_consumed()
        << " bytes (spec長度 " << ctx.header_size_in_bytes << " bytes) ===\n";
    out << "備註：以上「N/M 個機率被更新」中，被更新的機率的『最終數值』"
           "需要真正的 VP9 預設機率表(spec Annex / libvpx)搭配 inv_remap_prob "
           "才能算出，這裡沒有內嵌那份表，所以只回報有沒有更新、更新了幾個。\n";

  } catch (const vp9hdr::BoundaryReached &) {
    out << "\n[!] 已到達加密邊界，compressed_header 在階段「" << stage
        << "」中斷。\n";
    out << "    已消耗 " << pbr.bytes_consumed() << " bytes"
        << " (spec 宣告長度為 " << ctx.header_size_in_bytes << " bytes)\n";
    if (stage == "coef_probs")
      out << "    中斷於 coef_probs[txSz=" << coef_txsz_reached << "]，"
          << "此群組截至中斷已有 " << coef_updated << "/" << coef_total
          << " 個機率更新完成\n";
    out << "    這代表此 frame 的 compressed_header 本身就已經被 CRIWARE 切入加密，"
           "後面（含 skip_prob/inter相關機率, 以及整個 tile data）"
           "在沒有金鑰的情況下完全無法還原。\n";
    if (!reached_skip)
      out << "    尚未讀到: skip_prob, "
          << (ctx.frame_is_intra ? "(此frame是intra，之後就沒別的了)"
                                  : "inter_mode_probs/interp_filter_probs/"
                                    "is_inter_prob/reference_mode(+probs)/"
                                    "y_mode_probs/partition_probs/mv_probs")
          << "\n";
    else if (!reached_inter_section && !ctx.frame_is_intra)
      out << "    尚未讀到: inter_mode_probs/interp_filter_probs/is_inter_prob/"
             "reference_mode(+probs)/y_mode_probs/partition_probs/mv_probs\n";
  }
}
