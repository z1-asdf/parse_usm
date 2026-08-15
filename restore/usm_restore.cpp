#include <algorithm>
#include <array>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#endif

#include "vp9_header_parser_silent.h"

// ------------------------------------------------------------
// 位元組端序定義與基礎讀取工具
// ------------------------------------------------------------
enum class ENDIAN { BIG, LITTLE };

template <typename uint_type>
uint_type peek_uint(const uint8_t *ptr, ENDIAN endian = ENDIAN::BIG) {
  static_assert(std::is_unsigned<uint_type>::value, "只允許 unsigned 數字類別");
  constexpr size_t byteCount = sizeof(uint_type);

  uint_type result = 0;
  if (endian == ENDIAN::BIG) {
    for (size_t i = 0; i < byteCount; ++i) {
      result <<= 8;
      result |= static_cast<uint_type>(ptr[i]);
    }
  } else if (endian == ENDIAN::LITTLE) {
    for (size_t i = 0; i < byteCount; ++i) {
      result |= static_cast<uint_type>(ptr[i]) << (8 * i);
    }
  } else {
    throw std::logic_error("未知的 endian 類別");
  }

  return result;
}

template <typename uint_type>
uint_type ptr_to_uint(const uint8_t *&ptr, ENDIAN endian = ENDIAN::BIG) {
  uint_type tp = peek_uint<uint_type>(ptr, endian);
  ptr += sizeof(uint_type);
  return tp;
}

const size_t CHUNK_HEADER_SIZE = 8;

// ------------------------------------------------------------
// USM 影音金鑰結構與解密 (CRI Sofdec2)
// ------------------------------------------------------------
struct KeyResult {
  uint32_t key1 = 0;
  uint32_t key2 = 0;
  uint64_t key64 = 0;
};

struct UsmKeys {
  std::array<uint8_t, 0x40> video_key; // 0x40 byte 的影像金鑰遮罩 (Video Key)
  std::array<uint8_t, 0x20> audio_key; // 0x20 byte 的音訊金鑰遮罩 (Audio Key)
};

UsmKeys generate_usm_keys(uint32_t key1, uint32_t key2) {
  uint8_t k1[4] = {static_cast<uint8_t>((key1 >> 24) & 0xFF),
                   static_cast<uint8_t>((key1 >> 16) & 0xFF),
                   static_cast<uint8_t>((key1 >> 8) & 0xFF),
                   static_cast<uint8_t>(key1 & 0xFF)};
  uint8_t k2[4] = {static_cast<uint8_t>((key2 >> 24) & 0xFF),
                   static_cast<uint8_t>((key2 >> 16) & 0xFF),
                   static_cast<uint8_t>((key2 >> 8) & 0xFF),
                   static_cast<uint8_t>(key2 & 0xFF)};

  uint8_t key[0x20];
  key[0x00] = k1[0];
  key[0x01] = k1[1];
  key[0x02] = k1[2];
  key[0x03] = static_cast<uint8_t>(k1[3] - 0x34);
  key[0x04] = static_cast<uint8_t>(k2[0] + 0xF9);
  key[0x05] = static_cast<uint8_t>(k2[1] ^ 0x13);
  key[0x06] = static_cast<uint8_t>(k2[2] + 0x61);
  key[0x07] = key[0x00] ^ 0xFF;
  key[0x08] = static_cast<uint8_t>(key[0x01] + key[0x02]);
  key[0x09] = static_cast<uint8_t>(key[0x01] - key[0x07]);
  key[0x0A] = key[0x02] ^ 0xFF;
  key[0x0B] = key[0x01] ^ 0xFF;
  key[0x0C] = static_cast<uint8_t>(key[0x0B] + key[0x09]);
  key[0x0D] = static_cast<uint8_t>(key[0x08] - key[0x03]);
  key[0x0E] = key[0x0D] ^ 0xFF;
  key[0x0F] = static_cast<uint8_t>(key[0x0A] - key[0x0B]);
  key[0x10] = static_cast<uint8_t>(key[0x08] - key[0x0F]);
  key[0x11] = key[0x10] ^ key[0x07];
  key[0x12] = key[0x0F] ^ 0xFF;
  key[0x13] = key[0x03] ^ 0x10;
  key[0x14] = static_cast<uint8_t>(key[0x04] - 0x32);
  key[0x15] = static_cast<uint8_t>(key[0x05] + 0xED);
  key[0x16] = key[0x06] ^ 0xF3;
  key[0x17] = static_cast<uint8_t>(key[0x13] - key[0x0F]);
  key[0x18] = static_cast<uint8_t>(key[0x15] + key[0x07]);
  key[0x19] = static_cast<uint8_t>(0x21 - key[0x13]);
  key[0x1A] = key[0x14] ^ key[0x17];
  key[0x1B] = static_cast<uint8_t>(key[0x16] + key[0x16]);
  key[0x1C] = static_cast<uint8_t>(key[0x17] + 0x44);
  key[0x1D] = static_cast<uint8_t>(key[0x03] + key[0x04]);
  key[0x1E] = static_cast<uint8_t>(key[0x05] - key[0x16]);
  key[0x1F] = key[0x1D] ^ key[0x13];

  static const uint8_t audio_t[4] = {'U', 'R', 'U', 'C'};

  UsmKeys keys;
  for (int i = 0; i < 0x20; ++i) {
    keys.video_key[i] = key[i];
    keys.video_key[0x20 + i] = key[i] ^ 0xFF;
    keys.audio_key[i] = (i % 2 != 0) ? audio_t[(i >> 1) % 4]
                                     : static_cast<uint8_t>(key[i] ^ 0xFF);
  }
  return keys;
}

UsmKeys generate_usm_keys(uint64_t key_num) {
  uint8_t k1[4], k2[4];
  for (int i = 0; i < 4; ++i) {
    k1[i] = static_cast<uint8_t>((key_num >> (8 * i)) & 0xFF);
    k2[i] = static_cast<uint8_t>((key_num >> (8 * (4 + i))) & 0xFF);
  }
  uint32_t key1 = (static_cast<uint32_t>(k1[0]) << 24) |
                  (static_cast<uint32_t>(k1[1]) << 16) |
                  (static_cast<uint32_t>(k1[2]) << 8) |
                  static_cast<uint32_t>(k1[3]);
  uint32_t key2 = (static_cast<uint32_t>(k2[0]) << 24) |
                  (static_cast<uint32_t>(k2[1]) << 16) |
                  (static_cast<uint32_t>(k2[2]) << 8) |
                  static_cast<uint32_t>(k2[3]);
  return generate_usm_keys(key1, key2);
}

void decrypt_video_packet(std::vector<char> &packet,
                          const std::array<uint8_t, 0x40> &video_key) {
  if (packet.size() < 0x40)
    return;
  size_t size = packet.size() - 0x40;
  if (size < 0x200)
    return;

  uint8_t *data = reinterpret_cast<uint8_t *>(packet.data());
  const uint8_t *vm1 = video_key.data();
  const uint8_t *vm2 = video_key.data() + 0x20;

  // 階段 1：從 offset 0x140 開始 (即 payload + 0x40 + 0x100)
  size_t first_start = 0x40 + 0x100;
  size_t first_size = size - 0x100;
  size_t full_blocks = first_size / 0x20;
  size_t tail_size = first_size & 0x1F;

  uint8_t mask[0x20];
  std::memcpy(mask, vm2, 0x20);

  size_t pos = first_start;
  for (size_t b = 0; b < full_blocks; ++b) {
    for (size_t i = 0; i < 0x20; ++i) {
      uint8_t enc = data[pos + i];
      uint8_t plain = enc ^ mask[i];
      data[pos + i] = plain;
      mask[i] = plain ^ vm2[i];
    }
    pos += 0x20;
  }

  if (tail_size > 0) {
    for (size_t i = 0; i < tail_size; ++i) {
      data[pos + i] ^= mask[i];
    }
  }

  // 階段 2：前 0x100 位元組 (8 個 32 位元組區塊)，從 0x40 開始
  std::memcpy(mask, vm1, 0x20);
  for (size_t block = 0; block < 8; ++block) {
    size_t p = 0x40 + block * 0x20;
    size_t p2 = p + 0x100;
    for (size_t i = 0; i < 0x20; ++i) {
      uint8_t next_mask = mask[i] ^ data[p2 + i];
      data[p + i] ^= next_mask;
      mask[i] = next_mask;
    }
  }
}

// ============================================================
// 第一層：Chunk 結構體與說明
// ============================================================

// USM 底層原始 Chunk 結構
struct ChunkHeader {
  char magic[4];         // Chunk 識別 Magic
  uint32_t payload_size; // Payload 資料大端序長度 (bytes)
  std::vector<char>
      payload_data; // Payload 原始資料 (包含 ChunkPayload 標頭與內文)
};

// Chunk Payload 內部標頭解析結構
struct ChunkPayload {
  uint8_t unknown_1;   // offset 0: 未知位元組 1
  uint8_t data_offset; // offset 1: 實際內容資料偏移 (自 Chunk 標頭起算)
  uint16_t padding;    // offset 2~3: 區塊結尾填充大小 (bytes)
  uint8_t channel;     // offset 4: 通道編號
  uint16_t unknown_2;  // offset 5~6: 未知位元組 2
  uint8_t type_raw;    // offset 7: 原始 Payload 種類 (0: stream 影音, 1: header
                       // 檔頭, 2: section_end, 3: seek)
  uint32_t frame_time; // offset 8~11: 幀時間 / 幀計數
  uint32_t frame_rate; // offset 12~15: 幀率 (Frame Rate)
  uint64_t unknown_3;  // offset 16~23: 未知位元組 3

  std::vector<char>
      data; // offset 24+: 扣除標頭與尾部 Padding 後的實際 Payload 數據

  ChunkPayload() = default;
  ChunkPayload(const std::vector<char> &chrs) {
    if (chrs.size() < 25)
      throw std::out_of_range("解析 Payload 時傳入的 vector 過小。");

    const uint8_t *ptr = reinterpret_cast<const uint8_t *>(chrs.data());

    unknown_1 = *ptr;
    ++ptr;
    data_offset = *ptr;
    ++ptr;
    padding = ptr_to_uint<uint16_t>(ptr);
    channel = *ptr;
    ++ptr;
    unknown_2 = ptr_to_uint<uint16_t>(ptr);
    type_raw = *ptr;
    ++ptr;
    frame_time = ptr_to_uint<uint32_t>(ptr);
    frame_rate = ptr_to_uint<uint32_t>(ptr);
    unknown_3 = ptr_to_uint<uint64_t>(ptr);

    if (static_cast<size_t>(padding) > chrs.size() - 24)
      throw std::out_of_range("解析 Payload 時 padding 大於剩餘資料長度。");

    data = std::vector<char>(chrs.begin() + 24, chrs.end() - padding);
  }
};

// ============================================================
// 第二層：IVF 結構體與說明
// ============================================================

// IVF 檔案標頭結構 (DKIF, 32 bytes)
struct IVF_Header {
  char magic[4];          // bytes 0-3: 簽章識別碼 (例如 'DKIF')
  uint16_t version;       // bytes 4-5: IVF 規格版本 (應為 0)
  uint16_t header_length; // bytes 6-7: IVF 檔頭大小 (bytes, 通常為 32)
  char codec[4];          // bytes 8-11: 編碼器 FourCC (例如 'VP90', 'VP80')
  uint16_t width;         // bytes 12-13: 畫面像素寬度
  uint16_t height;        // bytes 14-15: 畫面像素高度
  uint32_t frame_rate;    // bytes 16-19: 幀率 / 時間分母
  uint32_t time;          // bytes 20-23: 時間基數 / 時間分子
  uint32_t frames_number; // bytes 24-27: 宣告總幀數
  uint32_t unused;        // bytes 28-31: 未使用 / 保留欄位

  IVF_Header() = default;
  IVF_Header(const std::vector<char> &data, size_t offset = 0) {
    if (data.size() < offset + 32) {
      throw std::out_of_range("IVF Header 資料長度不足 32 bytes");
    }
    const uint8_t *ptr =
        reinterpret_cast<const uint8_t *>(data.data()) + offset;

    std::memcpy(magic, ptr, 4);
    ptr += 4;
    version = ptr_to_uint<uint16_t>(ptr, ENDIAN::LITTLE);
    header_length = ptr_to_uint<uint16_t>(ptr, ENDIAN::LITTLE);
    std::memcpy(codec, ptr, 4);
    ptr += 4;
    width = ptr_to_uint<uint16_t>(ptr, ENDIAN::LITTLE);
    height = ptr_to_uint<uint16_t>(ptr, ENDIAN::LITTLE);
    frame_rate = ptr_to_uint<uint32_t>(ptr, ENDIAN::LITTLE);
    time = ptr_to_uint<uint32_t>(ptr, ENDIAN::LITTLE);
    frames_number = ptr_to_uint<uint32_t>(ptr, ENDIAN::LITTLE);
    unused = ptr_to_uint<uint32_t>(ptr, ENDIAN::LITTLE);
  }
};

// 單一 IVF 幀封包結構
struct IVF_frame_data {
  uint32_t size;          // bytes 0~3: Frame 數據長度 (bytes)
  uint64_t timestamp;     // bytes 4~11: 時間戳記 (64-bit integer)
  std::vector<char> data; // Frame 實際 VP9 Bitstream 數據

  IVF_frame_data() = default;
  IVF_frame_data(const std::vector<char> &raw_payload, size_t offset) {
    if (raw_payload.size() < offset + 12) {
      throw std::out_of_range("IVF Frame Header 資料長度不足 12 bytes");
    }
    const uint8_t *ptr =
        reinterpret_cast<const uint8_t *>(raw_payload.data()) + offset;

    size = ptr_to_uint<uint32_t>(ptr, ENDIAN::LITTLE);
    timestamp = ptr_to_uint<uint64_t>(ptr, ENDIAN::LITTLE);

    if (raw_payload.size() < offset + 12 + size) {
      throw std::out_of_range("IVF Frame 聲明之資料長度超出 payload 範圍");
    }
    data.assign(reinterpret_cast<const char *>(ptr),
                reinterpret_cast<const char *>(ptr) + size);
  }
};

// 完整 IVF 串流容器
struct IVF_Stream {
  bool has_header = false;            // 是否有包含 DKIF 檔頭
  IVF_Header header;                  // IVF 檔頭資訊
  std::vector<IVF_frame_data> frames; // 依序排列的所有 IVF Frame Packets 列表
};

// ============================================================
// 第三層：VP9 結構體與說明
// ============================================================

// VP9 單一 Frame 語法結構解析結果
struct VP9ParsedFrame {
  size_t frame_index;  // Frame 序號 (1-based)
  uint32_t frame_size; // Frame 數據大小 (bytes)
  uint64_t timestamp;  // Frame 時間戳記
  bool is_encrypted;   // 是否採 CRI 滾動加密 (payload 剩餘長度 >= 0x240)
  VP9FrameContext
      context; // VP9 Frame 標頭 Context 結構 (定義於 vp9_header_parser.h)
};

// ------------------------------------------------------------
// 單一 Chunk 解析 (無控制台輸出)
// ------------------------------------------------------------
bool parse_one_chunk(std::ifstream &ifs, size_t chunk_offset,
                     ChunkHeader &chunk) {
  auto read_bytes = [&](std::streamoff offset, char *buffer,
                        std::streamsize size) -> bool {
    ifs.seekg(offset);
    return static_cast<bool>(ifs.read(buffer, size));
  };

  char magic_temp[4] = {0};
  if (!read_bytes(chunk_offset, magic_temp, 4))
    return false;
  std::memcpy(chunk.magic, magic_temp, 4);

  char payload_size_temp[4];
  if (!read_bytes(chunk_offset + 4, payload_size_temp, 4))
    return false;

  const uint8_t *size_ptr =
      reinterpret_cast<const uint8_t *>(payload_size_temp);
  chunk.payload_size = ptr_to_uint<uint32_t>(size_ptr, ENDIAN::BIG);

  chunk.payload_data.resize(chunk.payload_size);
  if (!read_bytes(chunk_offset + 8, chunk.payload_data.data(),
                  chunk.payload_size))
    return false;

  return true;
}

// ------------------------------------------------------------
// 三大層級解析函式實作
// ------------------------------------------------------------

std::vector<ChunkHeader> parse_usm_chunks(const std::string &filepath) {
  std::ifstream file(filepath, std::ios::binary | std::ios::ate);
  if (!file.is_open())
    return {};

  std::streamsize total_file_size_ss = file.tellg();
  if (total_file_size_ss <= 0 || total_file_size_ss < 8) {
    file.close();
    return {};
  }
  uint64_t total_file_size = static_cast<uint64_t>(total_file_size_ss);

  std::vector<ChunkHeader> chunks;
  uint64_t current_offset = 0;

  while (current_offset < total_file_size) {
    if (current_offset + CHUNK_HEADER_SIZE >= total_file_size)
      break;
    ChunkHeader chunk;
    if (!parse_one_chunk(file, current_offset, chunk))
      break;

    chunks.push_back(chunk);
    current_offset += chunk.payload_size + CHUNK_HEADER_SIZE;
    if (current_offset > total_file_size)
      break;
  }

  file.close();
  return chunks;
}

// ------------------------------------------------------------
// [函式 二]：解析第二層 - 解出 IVF 檔頭與所有 Frame Packets 列表
// (可選傳入金鑰自動完成視訊解密)
// ------------------------------------------------------------
IVF_Stream parse_ivf_stream(const std::vector<ChunkHeader> &chunks,
                            bool decrypt = false,
                            const UsmKeys *keys = nullptr) {
  IVF_Stream ivf_stream;

  for (const auto &chunk : chunks) {
    ChunkPayload payload(chunk.payload_data);
    if (payload.type_raw != 0)
      continue; // 僅讀取 stream (影音) 類型的 payload

    std::vector<char> stream_data = payload.data;
    if (decrypt && keys != nullptr) {
      decrypt_video_packet(stream_data, keys->video_key);
    }

    size_t offset = 0;

    // 首個包含 DKIF 檔頭的區塊
    if (!ivf_stream.has_header) {
      if (stream_data.size() >= 32 &&
          std::memcmp(stream_data.data(), "DKIF", 4) == 0) {
        ivf_stream.header = IVF_Header(stream_data, 0);
        ivf_stream.has_header = true;
        offset = (ivf_stream.header.header_length == 0)
                     ? 32
                     : ivf_stream.header.header_length;
      } else {
        continue; // 尚未遇到檔頭前的數據跳過
      }
    } else {
      // 若後續 chunk 又重複帶 DKIF 標頭，跳過標頭 offset
      if (stream_data.size() >= 32 &&
          std::memcmp(stream_data.data(), "DKIF", 4) == 0) {
        offset = 32;
      }
    }

    // 連續解出該 Payload 內包含的所有 IVF Frame Packets
    while (offset + 12 <= stream_data.size()) {
      try {
        IVF_frame_data frame(stream_data, offset);
        uint64_t next_offset = offset + 12 + frame.size;
        if (next_offset > stream_data.size())
          break;

        ivf_stream.frames.push_back(std::move(frame));
        offset = static_cast<size_t>(next_offset);
      } catch (const std::exception &) {
        break;
      }
    }
  }

  return ivf_stream;
}

// ------------------------------------------------------------
// [函式 三]：解析第三層 - 解出 VP9 Frame Header 結構列表
// ------------------------------------------------------------
std::vector<VP9ParsedFrame> parse_vp9_frames(const IVF_Stream &ivf_stream) {
  std::vector<VP9ParsedFrame> vp9_frames;

  size_t idx = 1;
  for (const auto &frame : ivf_stream.frames) {
    VP9ParsedFrame vp9_frame;
    vp9_frame.frame_index = idx++;
    vp9_frame.frame_size = frame.size;
    vp9_frame.timestamp = frame.timestamp;

    const uint8_t *preview_ptr =
        reinterpret_cast<const uint8_t *>(frame.data.data());
    bool enc = frame.data.size() >= 0x240;
    vp9_frame.is_encrypted = enc;

    const uint8_t *end_ptr = nullptr;
    if (enc && frame.data.size() >= 0x40) {
      end_ptr = preview_ptr + 0x40;
    } else {
      end_ptr = preview_ptr + frame.data.size();
    }

    parse_vp9_uncompressed_header_silent(preview_ptr, end_ptr,
                                         vp9_frame.context);
    if (vp9_frame.context.uncompressed_ok) {
      parse_vp9_compressed_header_silent(end_ptr, vp9_frame.context);
    }

    vp9_frames.push_back(vp9_frame);
  }

  return vp9_frames;
}

// ------------------------------------------------------------
// 輔助函式：匯出 IVF 檔案
// ------------------------------------------------------------
bool export_ivf_file(const std::string &out_ivf_file,
                     const IVF_Stream &ivf_stream) {
  if (!ivf_stream.has_header || ivf_stream.frames.empty())
    return false;

  std::ofstream out(out_ivf_file, std::ios::binary);
  if (!out.is_open())
    return false;

  // 寫入 32-byte IVF Header
  char header_bytes[32] = {0};
  std::memcpy(header_bytes, "DKIF", 4);
  *reinterpret_cast<uint16_t *>(header_bytes + 4) = ivf_stream.header.version;
  *reinterpret_cast<uint16_t *>(header_bytes + 6) = 32; // header_length
  std::memcpy(header_bytes + 8, ivf_stream.header.codec, 4);
  *reinterpret_cast<uint16_t *>(header_bytes + 12) = ivf_stream.header.width;
  *reinterpret_cast<uint16_t *>(header_bytes + 14) = ivf_stream.header.height;
  *reinterpret_cast<uint32_t *>(header_bytes + 16) =
      ivf_stream.header.frame_rate;
  *reinterpret_cast<uint32_t *>(header_bytes + 20) = ivf_stream.header.time;
  *reinterpret_cast<uint32_t *>(header_bytes + 24) =
      static_cast<uint32_t>(ivf_stream.frames.size());

  out.write(header_bytes, 32);

  // 依序寫入 Frame Headers 與 Data
  for (const auto &f : ivf_stream.frames) {
    char frame_hdr[12];
    *reinterpret_cast<uint32_t *>(frame_hdr) = f.size;
    *reinterpret_cast<uint64_t *>(frame_hdr + 4) = f.timestamp;
    out.write(frame_hdr, 12);
    out.write(f.data.data(), f.size);
  }

  out.close();
  return true;
}

// ============================================================
// 金鑰破解 (Crack Key Solver) 模組實作
// ============================================================

struct Candidate {
  int64_t score = 0;
  std::array<uint8_t, 32> v{};
};

using ScoreMatrixUnigram = std::vector<std::array<uint32_t, 256>>;
using ScoreMatrixBigram = std::vector<std::vector<uint32_t>>;

static inline int64_t calculate_bg_score(const ScoreMatrixBigram &bigram,
                                         int index, uint8_t left, uint8_t right,
                                         int zero_w, int ff_w) {
  uint32_t pair_ff = (static_cast<uint32_t>(left) << 8) | right;
  uint32_t pair_zero =
      (static_cast<uint32_t>(left ^ 0xFF) << 8) | (right ^ 0xFF);
  return static_cast<int64_t>(ff_w) * bigram[index][pair_ff] +
         static_cast<int64_t>(zero_w) * bigram[index][pair_zero];
}

static void prune_candidates(std::vector<Candidate> &candidates, size_t beam) {
  if (candidates.size() <= beam)
    return;
  std::partial_sort(
      candidates.begin(), candidates.begin() + beam, candidates.end(),
      [](const Candidate &a, const Candidate &b) { return a.score > b.score; });
  candidates.resize(beam);
}

static bool solve_vm1_bigram(const ScoreMatrixUnigram &unigram,
                             const ScoreMatrixBigram &bigram, size_t beam_size,
                             size_t l1_beam_size, int zero_w, int ff_w,
                             std::array<uint8_t, 32> &best_vm1) {
  size_t l1_beam = std::max<size_t>(1, l1_beam_size);
  size_t beam = std::max<size_t>(1, beam_size);

  // Level 1: 枚舉 v1, v2
  std::vector<Candidate> level1;
  level1.reserve(256 * 256);

  for (int v1 = 0; v1 < 256; ++v1) {
    for (int v2 = 0; v2 < 256; ++v2) {
      Candidate c;
      c.v[1] = static_cast<uint8_t>(v1);
      c.v[2] = static_cast<uint8_t>(v2);
      c.v[8] = static_cast<uint8_t>((c.v[2] + c.v[1]) & 0xFF);
      c.v[10] = static_cast<uint8_t>(c.v[2] ^ 0xFF);
      c.v[11] = static_cast<uint8_t>(c.v[1] ^ 0xFF);
      c.v[15] = static_cast<uint8_t>((c.v[10] - c.v[11]) & 0xFF);
      c.v[16] = static_cast<uint8_t>((c.v[8] - c.v[15]) & 0xFF);
      c.v[18] = static_cast<uint8_t>(c.v[15] ^ 0xFF);

      c.score = unigram[1][c.v[1]] + unigram[2][c.v[2]] + unigram[8][c.v[8]] +
                unigram[10][c.v[10]] + unigram[11][c.v[11]] +
                unigram[15][c.v[15]] + unigram[16][c.v[16]] +
                unigram[18][c.v[18]] +
                calculate_bg_score(bigram, 1, c.v[1], c.v[2], zero_w, ff_w) +
                calculate_bg_score(bigram, 10, c.v[10], c.v[11], zero_w, ff_w) +
                calculate_bg_score(bigram, 15, c.v[15], c.v[16], zero_w, ff_w);

      level1.push_back(c);
    }
  }

  prune_candidates(level1, l1_beam);
  if (level1.empty())
    return false;

  // Level 2 (Level 0 in variables): 擴展 v0
  std::vector<Candidate> level2;
  level2.reserve(level1.size() * 256);
  for (const auto &prev : level1) {
    for (int v0 = 0; v0 < 256; ++v0) {
      Candidate c = prev;
      c.v[0] = static_cast<uint8_t>(v0);
      c.v[7] = static_cast<uint8_t>(c.v[0] ^ 0xFF);
      c.v[9] = static_cast<uint8_t>((c.v[1] - c.v[7]) & 0xFF);
      c.v[12] = static_cast<uint8_t>((c.v[11] + c.v[9]) & 0xFF);
      c.v[17] = static_cast<uint8_t>(c.v[16] ^ c.v[7]);

      c.score +=
          unigram[0][c.v[0]] + unigram[7][c.v[7]] + unigram[9][c.v[9]] +
          unigram[12][c.v[12]] + unigram[17][c.v[17]] +
          calculate_bg_score(bigram, 0, c.v[0], c.v[1], zero_w, ff_w) +
          calculate_bg_score(bigram, 7, c.v[7], c.v[8], zero_w, ff_w) +
          calculate_bg_score(bigram, 8, c.v[8], c.v[9], zero_w, ff_w) +
          calculate_bg_score(bigram, 9, c.v[9], c.v[10], zero_w, ff_w) +
          calculate_bg_score(bigram, 11, c.v[11], c.v[12], zero_w, ff_w) +
          calculate_bg_score(bigram, 16, c.v[16], c.v[17], zero_w, ff_w) +
          calculate_bg_score(bigram, 17, c.v[17], c.v[18], zero_w, ff_w);

      level2.push_back(c);
    }
  }

  prune_candidates(level2, beam);
  if (level2.empty())
    return false;

  // Level 3: 擴展 v3
  std::vector<Candidate> level3;
  level3.reserve(level2.size() * 256);
  for (const auto &prev : level2) {
    for (int v3 = 0; v3 < 256; ++v3) {
      Candidate c = prev;
      c.v[3] = static_cast<uint8_t>(v3);
      c.v[13] = static_cast<uint8_t>((c.v[8] - c.v[3]) & 0xFF);
      c.v[14] = static_cast<uint8_t>(c.v[13] ^ 0xFF);
      c.v[19] = static_cast<uint8_t>(c.v[3] ^ 0x10);
      c.v[23] = static_cast<uint8_t>((c.v[19] - c.v[15]) & 0xFF);
      c.v[25] = static_cast<uint8_t>((0x21 - c.v[19]) & 0xFF);
      c.v[28] = static_cast<uint8_t>((c.v[23] + 0x44) & 0xFF);

      c.score +=
          unigram[3][c.v[3]] + unigram[13][c.v[13]] + unigram[14][c.v[14]] +
          unigram[19][c.v[19]] + unigram[23][c.v[23]] + unigram[25][c.v[25]] +
          unigram[28][c.v[28]] +
          calculate_bg_score(bigram, 2, c.v[2], c.v[3], zero_w, ff_w) +
          calculate_bg_score(bigram, 12, c.v[12], c.v[13], zero_w, ff_w) +
          calculate_bg_score(bigram, 13, c.v[13], c.v[14], zero_w, ff_w) +
          calculate_bg_score(bigram, 14, c.v[14], c.v[15], zero_w, ff_w) +
          calculate_bg_score(bigram, 18, c.v[18], c.v[19], zero_w, ff_w);

      level3.push_back(c);
    }
  }

  prune_candidates(level3, beam);
  if (level3.empty())
    return false;

  // Level 4: 擴展 v4
  std::vector<Candidate> level4;
  level4.reserve(level3.size() * 256);
  for (const auto &prev : level3) {
    for (int v4 = 0; v4 < 256; ++v4) {
      Candidate c = prev;
      c.v[4] = static_cast<uint8_t>(v4);
      c.v[20] = static_cast<uint8_t>((c.v[4] - 0x32) & 0xFF);
      c.v[26] = static_cast<uint8_t>(c.v[20] ^ c.v[23]);
      c.v[29] = static_cast<uint8_t>((c.v[3] + c.v[4]) & 0xFF);
      c.v[31] = static_cast<uint8_t>(c.v[29] ^ c.v[19]);

      c.score +=
          unigram[4][c.v[4]] + unigram[20][c.v[20]] + unigram[26][c.v[26]] +
          unigram[29][c.v[29]] + unigram[31][c.v[31]] +
          calculate_bg_score(bigram, 3, c.v[3], c.v[4], zero_w, ff_w) +
          calculate_bg_score(bigram, 19, c.v[19], c.v[20], zero_w, ff_w) +
          calculate_bg_score(bigram, 25, c.v[25], c.v[26], zero_w, ff_w) +
          calculate_bg_score(bigram, 28, c.v[28], c.v[29], zero_w, ff_w);

      level4.push_back(c);
    }
  }

  prune_candidates(level4, beam);
  if (level4.empty())
    return false;

  // Level 5: 擴展 v6
  std::vector<Candidate> level5;
  level5.reserve(level4.size() * 256);
  for (const auto &prev : level4) {
    for (int v6 = 0; v6 < 256; ++v6) {
      Candidate c = prev;
      c.v[6] = static_cast<uint8_t>(v6);
      c.v[22] = static_cast<uint8_t>(c.v[6] ^ 0xF3);
      c.v[27] = static_cast<uint8_t>((c.v[22] + c.v[22]) & 0xFF);

      c.score +=
          unigram[6][c.v[6]] + unigram[22][c.v[22]] + unigram[27][c.v[27]] +
          calculate_bg_score(bigram, 6, c.v[6], c.v[7], zero_w, ff_w) +
          calculate_bg_score(bigram, 26, c.v[26], c.v[27], zero_w, ff_w) +
          calculate_bg_score(bigram, 27, c.v[27], c.v[28], zero_w, ff_w);

      level5.push_back(c);
    }
  }

  prune_candidates(level5, beam);
  if (level5.empty())
    return false;

  // Level 6: 擴展 v5
  std::vector<Candidate> level6;
  level6.reserve(level5.size() * 256);
  for (const auto &prev : level5) {
    for (int v5 = 0; v5 < 256; ++v5) {
      Candidate c = prev;
      c.v[5] = static_cast<uint8_t>(v5);
      c.v[21] = static_cast<uint8_t>((c.v[5] + 0xED) & 0xFF);
      c.v[24] = static_cast<uint8_t>((c.v[21] + c.v[7]) & 0xFF);
      c.v[30] = static_cast<uint8_t>((c.v[5] - c.v[22]) & 0xFF);

      c.score +=
          unigram[5][c.v[5]] + unigram[21][c.v[21]] + unigram[24][c.v[24]] +
          unigram[30][c.v[30]] +
          calculate_bg_score(bigram, 4, c.v[4], c.v[5], zero_w, ff_w) +
          calculate_bg_score(bigram, 5, c.v[5], c.v[6], zero_w, ff_w) +
          calculate_bg_score(bigram, 20, c.v[20], c.v[21], zero_w, ff_w) +
          calculate_bg_score(bigram, 21, c.v[21], c.v[22], zero_w, ff_w) +
          calculate_bg_score(bigram, 22, c.v[22], c.v[23], zero_w, ff_w) +
          calculate_bg_score(bigram, 23, c.v[23], c.v[24], zero_w, ff_w) +
          calculate_bg_score(bigram, 24, c.v[24], c.v[25], zero_w, ff_w) +
          calculate_bg_score(bigram, 29, c.v[29], c.v[30], zero_w, ff_w) +
          calculate_bg_score(bigram, 30, c.v[30], c.v[31], zero_w, ff_w);

      level6.push_back(c);
    }
  }

  prune_candidates(level6, 1);
  if (level6.empty())
    return false;

  best_vm1 = level6[0].v;
  return true;
}

// ------------------------------------------------------------
// 高階介面函式：執行 USM 金鑰破解與選擇性導出還原影片
// ------------------------------------------------------------
bool crack_usm_key(const std::vector<ChunkHeader> &chunks, bool output_video,
                   KeyResult &out_key,
                   const std::string &out_ivf_file = "outputV.ivf",
                   const IVF_Stream *preparsed_ivf = nullptr,
                   const std::vector<VP9ParsedFrame> *preparsed_vp9 = nullptr) {
  (void)preparsed_vp9; // 可用於擴充進階語法約束

  ScoreMatrixUnigram unigram(32);
  ScoreMatrixBigram bigram(31, std::vector<uint32_t>(65536, 0));

  for (size_t i = 0; i < 32; ++i) {
    unigram[i].fill(0);
  }

  uint64_t sample_rows = 0;
  uint64_t odd_bigram_zero = 0;
  uint64_t odd_bigram_ff = 0;

  // 遍歷所有 Chunk 統計 @SFV 影片區塊
  for (const auto &chunk : chunks) {
    if (std::memcmp(chunk.magic, "@SFV", 4) != 0)
      continue;

    if (chunk.payload_data.size() < 25)
      continue;

    try {
      ChunkPayload payload(chunk.payload_data);
      if (payload.type_raw != 0) // 僅處理 stream 影音
        continue;

      size_t payload_size =
          chunk.payload_size - payload.data_offset - payload.padding;

      // 檢查 payload 大小是否達到加密最小門檻 (扣除 0x40 後 >= 0x200)
      if (payload_size < 0x40 + 0x200)
        continue;

      if (payload_size < 0x140)
        continue;

      size_t encrypted_size = payload_size - 0x140;
      encrypted_size -= (encrypted_size % 32);
      if (encrypted_size < 32)
        continue;

      // payload_data 包含 0..data_offset-1 (header)。實際 payload 在
      // data_offset 開始。 encrypted_start 距離 payload 起始點 0x140，所以距離
      // payload_data 起始點是 data_offset + 0x140。
      size_t start_in_payload_data = payload.data_offset + 0x140;

      const uint8_t *raw_ptr =
          reinterpret_cast<const uint8_t *>(chunk.payload_data.data());
      size_t num_blocks = encrypted_size / 32;

      uint8_t current_s[32] = {0};

      for (size_t b = 0; b < num_blocks; ++b) {
        size_t block_start = start_in_payload_data + b * 32;
        if (block_start + 32 > chunk.payload_data.size())
          break;

        for (size_t j = 0; j < 32; ++j) {
          current_s[j] ^= raw_ptr[block_start + j];
        }

        if (b % 2 == 0) {
          sample_rows++;
          for (size_t j = 0; j < 32; ++j) {
            unigram[j][current_s[j]]++;
            unigram[j][current_s[j] ^ 0xFF]++;
          }
          for (size_t j = 0; j < 31; ++j) {
            uint32_t pair_val =
                (static_cast<uint32_t>(current_s[j]) << 8) | current_s[j + 1];
            bigram[j][pair_val]++;
          }
        } else {
          for (size_t j = 0; j < 31; ++j) {
            uint8_t left = current_s[j];
            uint8_t right = current_s[j + 1];
            if (left == 0x00 && right == 0x00) {
              odd_bigram_zero++;
            } else if (left == 0xFF && right == 0xFF) {
              odd_bigram_ff++;
            }
          }
        }
      }
    } catch (const std::exception &) {
      continue;
    }
  }

  if (sample_rows == 0) {
    std::cerr << "[Crack Error] 找不到足以進行頻率分析的 @SFV 視訊加密區塊。\n";
    return false;
  }

  // 估算 Bigram 00 與 FF 權重 (BIGRAM_WEIGHT_TOTAL = 25, ADAPT_MIN_HITS = 100)
  uint64_t total_hits = odd_bigram_zero + odd_bigram_ff;
  int zero_weight = 10;
  int ff_weight = 4;

  if (total_hits >= 100) {
    double raw_ratio =
        (odd_bigram_ff > 0)
            ? (static_cast<double>(odd_bigram_zero) / odd_bigram_ff)
            : 5.0;
    double adjusted_ratio = std::max(1.0, std::min(5.0, raw_ratio));
    zero_weight = static_cast<int>(
        std::round(25.0 * adjusted_ratio / (1.0 + adjusted_ratio)));
    ff_weight = 25 - zero_weight;
  }

  // 執行 6-Stage 束搜尋推導 32-byte VM 遮罩 (beam_size = 50, l1_beam_size =
  // 300)
  std::array<uint8_t, 32> best_vm1{};
  if (!solve_vm1_bigram(unigram, bigram, 50, 300, zero_weight, ff_weight,
                        best_vm1)) {
    std::cerr << "[Crack Error] 束搜尋未找到有效候選金鑰遮罩。\n";
    return false;
  }

  // 逆向還原 key1 與 key2 (各 4 bytes)
  uint8_t k1[4] = {best_vm1[0], best_vm1[1], best_vm1[2],
                   static_cast<uint8_t>((best_vm1[3] + 0x34) & 0xFF)};
  uint8_t k2[4] = {static_cast<uint8_t>((best_vm1[4] - 0xF9) & 0xFF),
                   static_cast<uint8_t>(best_vm1[5] ^ 0x13),
                   static_cast<uint8_t>((best_vm1[6] - 0x61) & 0xFF), 0x00};

  out_key.key1 = (static_cast<uint32_t>(k1[0]) << 24) |
                 (static_cast<uint32_t>(k1[1]) << 16) |
                 (static_cast<uint32_t>(k1[2]) << 8) |
                 static_cast<uint32_t>(k1[3]);

  out_key.key2 = (static_cast<uint32_t>(k2[0]) << 24) |
                 (static_cast<uint32_t>(k2[1]) << 16) |
                 (static_cast<uint32_t>(k2[2]) << 8) |
                 static_cast<uint32_t>(k2[3]);

  out_key.key64 = 0;
  for (int i = 0; i < 4; ++i) {
    out_key.key64 |= (static_cast<uint64_t>(k1[i]) << (8 * i));
  }
  for (int i = 0; i < 4; ++i) {
    out_key.key64 |= (static_cast<uint64_t>(k2[i]) << (8 * (4 + i)));
  }

  // 若 output_video 為 true，進行解密並匯出 IVF 影片
  if (output_video) {
    UsmKeys keys = generate_usm_keys(out_key.key1, out_key.key2);
    IVF_Stream ivf_stream =
        preparsed_ivf ? *preparsed_ivf : parse_ivf_stream(chunks, true, &keys);
    if (preparsed_ivf) {
      // 若使用傳入的 IVF_Stream，重新解密 packet
      ivf_stream = parse_ivf_stream(chunks, true, &keys);
    }
    if (!export_ivf_file(out_ivf_file, ivf_stream)) {
      std::cerr << "[Export Error] 無法寫入解密後的 IVF 影片檔至: "
                << out_ivf_file << "\n";
      return false;
    }
  }

  return true;
}

// ------------------------------------------------------------
// 主程式展示 (支援金鑰破解與視訊還原)
// ------------------------------------------------------------
int main(int argc, char *argv[]) {
#ifdef _WIN32
  SetConsoleOutputCP(CP_UTF8);
#endif
  std::ios::sync_with_stdio(false);

  if (argc < 2) {
    std::cout << "USM 影音三層結構解析、金鑰自動破解與還原工具\n"
              << "使用方式：\n"
              << "  自動破解金鑰: " << argv[0] << " <輸入.usm>\n"
              << "  自動破解並導出影片: " << argv[0]
              << " <輸入.usm> <輸出.ivf>\n"
              << "  指定金鑰還原影片: " << argv[0]
              << " <輸入.usm> <輸出.ivf> <key1(hex)> <key2(hex)>\n";
    return 1;
  }

  std::string usm_file = argv[1];
  std::string ivf_file = (argc >= 3) ? argv[2] : "outputV.ivf";
  bool explicit_keys = (argc >= 5);

  // 1. 第一層解析：解出 Chunk vector
  std::cout << "[層級 1] 解析 USM 區塊結構...\n";
  std::vector<ChunkHeader> chunks = parse_usm_chunks(usm_file);
  if (chunks.empty()) {
    std::cerr << "錯誤：讀取或解析 USM 檔案失敗。\n";
    return 1;
  }
  std::cout << "  -> 成功解出 " << chunks.size() << " 個 Chunk 區塊。\n";

  KeyResult key_result;

  if (explicit_keys) {
    try {
      key_result.key1 = static_cast<uint32_t>(std::stoul(argv[3], nullptr, 16));
      key_result.key2 = static_cast<uint32_t>(std::stoul(argv[4], nullptr, 16));
      key_result.key64 =
          (static_cast<uint64_t>(key_result.key1) << 32) | key_result.key2;
    } catch (const std::exception &e) {
      std::cerr << "錯誤：key1 / key2 必須為十六進位數字 (" << e.what()
                << ")\n";
      return 1;
    }
    std::cout << "[模式] 使用手動指定的 Key1: 0x" << std::hex << std::uppercase
              << key_result.key1 << ", Key2: 0x" << key_result.key2 << std::dec
              << "\n";

    UsmKeys keys = generate_usm_keys(key_result.key64);
    IVF_Stream ivf_stream = parse_ivf_stream(chunks, true, &keys);
    if (!export_ivf_file(ivf_file, ivf_stream)) {
      std::cerr << "錯誤：寫入 IVF 檔案失敗。\n";
      return 1;
    }
    std::cout << "解密並還原 IVF 影片成功： " << ivf_file << "\n";
  } else {
    bool output_video = (argc >= 3);
    std::cout
        << "[模式] 啟動自動金鑰破解演算法 (Unigram/Bigram Beam Search)...\n";

    // 調用核心破解函式
    if (crack_usm_key(chunks, output_video, key_result, ivf_file)) {
      std::cout << "\n========================================\n";
      std::cout << " [Crack Success] 成功破解 USM 金鑰！\n";
      std::cout << "  Key1   : 0x" << std::hex << std::uppercase
                << key_result.key1 << "\n";
      std::cout << "  Key2   : 0x" << std::hex << std::uppercase
                << key_result.key2 << "\n";
      std::cout << "  Key64  : 0x" << std::hex << std::uppercase
                << key_result.key64 << std::dec << "\n";
      std::cout << "========================================\n\n";

      if (output_video) {
        std::cout << "已導出解密影片檔至: " << ivf_file << "\n";
      }
    } else {
      std::cerr << "金鑰破解失敗。\n";
      return 1;
    }
  }

  return 0;
}
