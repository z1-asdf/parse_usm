#include <algorithm>
#include <array>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iostream>
#include <string>
#include <type_traits>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#endif

// ------------------------------------------------------------
// 位元組端序定義與基礎讀取工具
// ------------------------------------------------------------
enum class ENDIAN { BIG, LITTLE };

template <typename uint_type>
inline uint_type peek_uint(const uint8_t *ptr, ENDIAN endian = ENDIAN::BIG) {
  static_assert(std::is_unsigned_v<uint_type>, "只允許 unsigned 數字類別");
  constexpr size_t byteCount = sizeof(uint_type);
  uint_type result = 0;
  if (endian == ENDIAN::BIG) {
    for (size_t i = 0; i < byteCount; ++i) {
      result = static_cast<uint_type>((result << 8) | ptr[i]);
    }
  } else {
    for (size_t i = 0; i < byteCount; ++i) {
      result = static_cast<uint_type>(
          result | (static_cast<uint_type>(ptr[i]) << (8 * i)));
    }
  }
  return result;
}

template <typename uint_type>
inline uint_type ptr_to_uint(const uint8_t *&ptr, ENDIAN endian = ENDIAN::BIG) {
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

void decrypt_video_packet(uint8_t *data, size_t size,
                          const std::array<uint8_t, 0x40> &video_key) {
  if (size < 0x240)
    return;

  const uint8_t *vm1 = video_key.data();
  const uint8_t *vm2 = video_key.data() + 0x20;

  // 階段 1：從 offset 0x140 開始 (即 payload + 0x40 + 0x100)
  size_t first_start = 0x140;
  size_t first_size = size - 0x140;
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
// 第一層：Chunk 結構體 (合併標頭與必要欄位)
// ============================================================

struct Chunk {
  char magic[4] = {0};       // Chunk 識別 Magic (例如 "@SFV", "#SFV")
  uint32_t payload_size = 0; // Payload 資料大端序長度 (bytes)
  uint8_t data_offset = 0;   // offset 1: 實際內容資料偏移 (通常為 0x18 = 24)
  uint16_t padding = 0;      // offset 2~3: 區塊結尾填充大小 (bytes)
  uint8_t type_raw = 0;      // offset 7: 原始 Payload 種類 (0: stream 影音)
  std::vector<char> payload_data; // Payload 完整原始資料
};

// ------------------------------------------------------------
// 串流讀取器 (Stream Reader / Iterator)
// ------------------------------------------------------------
class UsmReader {
private:
  std::string filepath_;
  std::ifstream file_;
  std::streamoff total_size_ = 0;

public:
  explicit UsmReader(const std::string &filepath)
      : filepath_(filepath), file_(filepath, std::ios::binary) {
    if (file_.is_open()) {
      file_.seekg(0, std::ios::end);
      total_size_ = file_.tellg();
      file_.seekg(0, std::ios::beg);
    }
  }

  bool is_open() const { return file_.is_open() && total_size_ >= 8; }
  uint64_t total_size() const {
    return total_size_ > 0 ? static_cast<uint64_t>(total_size_) : 0;
  }

  void rewind() {
    if (file_.is_open()) {
      file_.clear();
      file_.seekg(0, std::ios::beg);
    }
  }

  // 串流讀取下一個 Chunk (複用 chunk 記憶體空間)
  bool read_next(Chunk &chunk, bool read_payload = true) {
    if (!file_.is_open())
      return false;

    std::streamoff cur = file_.tellg();
    if (cur < 0 ||
        cur + static_cast<std::streamoff>(CHUNK_HEADER_SIZE) > total_size_) {
      return false;
    }

    char header[8];
    if (!file_.read(header, 8)) {
      return false;
    }

    std::memcpy(chunk.magic, header, 4);
    const uint8_t *size_ptr = reinterpret_cast<const uint8_t *>(header + 4);
    chunk.payload_size = ptr_to_uint<uint32_t>(size_ptr, ENDIAN::BIG);

    if (static_cast<uint64_t>(file_.tellg()) + chunk.payload_size >
        static_cast<uint64_t>(total_size_)) {
      return false;
    }

    if (!read_payload) {
      file_.seekg(chunk.payload_size, std::ios::cur);
      chunk.data_offset = 0;
      chunk.padding = 0;
      chunk.type_raw = 0xFF;
      chunk.payload_data.clear();
      return true;
    }

    chunk.payload_data.resize(chunk.payload_size);
    if (chunk.payload_size > 0) {
      if (!file_.read(chunk.payload_data.data(), chunk.payload_size)) {
        return false;
      }
    }

    // 快速擷取 Payload 標頭關鍵欄位 (至少需 24 bytes)
    if (chunk.payload_size >= 24) {
      const uint8_t *ptr =
          reinterpret_cast<const uint8_t *>(chunk.payload_data.data());
      chunk.data_offset = ptr[1];
      chunk.padding = peek_uint<uint16_t>(ptr + 2, ENDIAN::BIG);
      chunk.type_raw = ptr[7];
    } else {
      chunk.data_offset = 0;
      chunk.padding = 0;
      chunk.type_raw = 0xFF;
    }

    return true;
  }
};

// ------------------------------------------------------------
// 輔助函式：解密視訊 Chunk 並串流匯出還原檔案 (Zero-Copy 原處解密)
// ------------------------------------------------------------
bool export_file(const std::string &out_file, UsmReader &reader,
                 const UsmKeys &keys) {
  reader.rewind();
  std::ofstream out(out_file, std::ios::binary);
  if (!out.is_open())
    return false;

  size_t written_chunks = 0;
  Chunk chunk;

  while (reader.read_next(chunk)) {
    if (std::memcmp(chunk.magic, "@SFV", 4) != 0)
      continue;

    if (chunk.payload_data.size() < 24)
      continue;

    if (chunk.type_raw != 0)
      continue; // 僅處理 stream 影音

    if (chunk.payload_data.size() <
        static_cast<size_t>(chunk.data_offset + chunk.padding))
      continue;

    size_t stream_size =
        chunk.payload_data.size() - chunk.data_offset - chunk.padding;
    uint8_t *stream_ptr = reinterpret_cast<uint8_t *>(
        chunk.payload_data.data() + chunk.data_offset);

    decrypt_video_packet(stream_ptr, stream_size, keys.video_key);

    if (stream_size > 0) {
      out.write(reinterpret_cast<const char *>(stream_ptr), stream_size);
      written_chunks++;
    }
  }

  out.close();
  return (written_chunks > 0);
}

// ============================================================
// 金鑰破解 (Crack Key Solver) 模組實作
// ============================================================

struct Candidate {
  int64_t score = 0;
  std::array<uint8_t, 32> v{};
};

using ScoreMatrixUnigram = std::array<std::array<uint32_t, 256>, 32>;

struct ScoreMatrixBigram {
  std::vector<uint32_t> data;
  ScoreMatrixBigram() : data(31 * 65536, 0) {}

  inline uint32_t get(size_t index, uint32_t pair_val) const {
    return data[index * 65536 + pair_val];
  }

  inline void add(size_t index, uint32_t pair_val) {
    data[index * 65536 + pair_val]++;
  }
};

static inline int64_t calculate_bg_score(const ScoreMatrixBigram &bigram,
                                         int index, uint8_t left, uint8_t right,
                                         int zero_w, int ff_w) {
  uint32_t pair_ff = (static_cast<uint32_t>(left) << 8) | right;
  uint32_t pair_zero =
      (static_cast<uint32_t>(left ^ 0xFF) << 8) | (right ^ 0xFF);
  return static_cast<int64_t>(ff_w) * bigram.get(index, pair_ff) +
         static_cast<int64_t>(zero_w) * bigram.get(index, pair_zero);
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
// 輔助函式：累加單一 Chunk 的統計頻率資訊
// ------------------------------------------------------------
static void accumulate_chunk_statistics(
    const Chunk &chunk, ScoreMatrixUnigram &unigram, ScoreMatrixBigram &bigram,
    uint64_t &sample_rows, uint64_t &odd_bigram_zero, uint64_t &odd_bigram_ff) {
  if (std::memcmp(chunk.magic, "@SFV", 4) != 0)
    return;

  if (chunk.payload_data.size() < 24)
    return;

  if (chunk.type_raw != 0) // 僅處理 stream 影音
    return;

  if (chunk.payload_data.size() <
      static_cast<size_t>(chunk.data_offset + chunk.padding))
    return;

  size_t stream_size = chunk.payload_size - chunk.data_offset - chunk.padding;

  // 檢查 stream 大小是否達到加密最小門檻 (扣除 0x40 後 >= 0x200)
  if (stream_size < 0x240)
    return;

  size_t encrypted_size = stream_size - 0x140;
  encrypted_size -= (encrypted_size % 32);
  if (encrypted_size < 32)
    return;

  size_t start_in_payload_data = chunk.data_offset + 0x140;
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
        bigram.add(j, pair_val);
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
}

// ------------------------------------------------------------
// 輔助函式：以第一包視訊資料驗證金鑰是否收斂 (DKIF 標頭匹配)
// ------------------------------------------------------------
static bool test_key_convergence(const std::vector<char> &first_video_packet,
                                 uint32_t key1, uint32_t key2) {
  if (first_video_packet.size() < 32)
    return false;
  std::vector<char> test_packet = first_video_packet;
  UsmKeys test_keys = generate_usm_keys(key1, key2);
  decrypt_video_packet(reinterpret_cast<uint8_t *>(test_packet.data()),
                       test_packet.size(), test_keys.video_key);
  return (std::memcmp(test_packet.data(), "DKIF", 4) == 0);
}

// ------------------------------------------------------------
// 輔助函式：自 32-byte VM1 遮罩計算 KeyResult
// ------------------------------------------------------------
static KeyResult build_key_result(const std::array<uint8_t, 32> &vm1) {
  uint8_t k1[4] = {vm1[0], vm1[1], vm1[2],
                   static_cast<uint8_t>((vm1[3] + 0x34) & 0xFF)};
  uint8_t k2[4] = {static_cast<uint8_t>((vm1[4] - 0xF9) & 0xFF),
                   static_cast<uint8_t>(vm1[5] ^ 0x13),
                   static_cast<uint8_t>((vm1[6] - 0x61) & 0xFF), 0x00};

  KeyResult res;
  res.key1 = (static_cast<uint32_t>(k1[0]) << 24) |
             (static_cast<uint32_t>(k1[1]) << 16) |
             (static_cast<uint32_t>(k1[2]) << 8) | static_cast<uint32_t>(k1[3]);

  res.key2 = (static_cast<uint32_t>(k2[0]) << 24) |
             (static_cast<uint32_t>(k2[1]) << 16) |
             (static_cast<uint32_t>(k2[2]) << 8) | static_cast<uint32_t>(k2[3]);

  res.key64 = 0;
  for (int i = 0; i < 4; ++i) {
    res.key64 |= (static_cast<uint64_t>(k1[i]) << (8 * i));
  }
  for (int i = 0; i < 4; ++i) {
    res.key64 |= (static_cast<uint64_t>(k2[i]) << (8 * (4 + i)));
  }
  return res;
}

// ------------------------------------------------------------
// 高階介面函式：執行 USM 串流金鑰破解 (動態批次收斂)
// ------------------------------------------------------------
bool crack_usm_key(UsmReader &reader, bool output_video, KeyResult &out_key,
                   const std::string &out_ivf_file = "outputV.ivf") {

  reader.rewind();

  ScoreMatrixUnigram unigram{};
  ScoreMatrixBigram bigram;

  uint64_t sample_rows = 0;
  uint64_t odd_bigram_zero = 0;
  uint64_t odd_bigram_ff = 0;

  std::vector<char> first_video_packet;
  size_t total_chunks_read = 0;
  size_t batch_chunks_read = 0;
  constexpr size_t BATCH_SIZE = 100;
  bool converged = false;

  auto calculate_weights = [&](int &zero_w, int &ff_w) {
    zero_w = 10;
    ff_w = 4;
    uint64_t total_hits = odd_bigram_zero + odd_bigram_ff;
    if (total_hits >= 100) {
      double raw_ratio =
          (odd_bigram_ff > 0)
              ? (static_cast<double>(odd_bigram_zero) / odd_bigram_ff)
              : 5.0;
      double adjusted_ratio = std::clamp(raw_ratio, 1.0, 5.0);
      zero_w = static_cast<int>(
          std::round(25.0 * adjusted_ratio / (1.0 + adjusted_ratio)));
      ff_w = 25 - zero_w;
    }
  };

  Chunk chunk;
  while (reader.read_next(chunk)) {
    total_chunks_read++;
    batch_chunks_read++;

    // 暫存第一包視訊資料供驗證
    if (first_video_packet.empty() &&
        std::memcmp(chunk.magic, "@SFV", 4) == 0 && chunk.type_raw == 0 &&
        chunk.payload_data.size() >=
            static_cast<size_t>(chunk.data_offset + chunk.padding)) {
      first_video_packet.assign(chunk.payload_data.begin() + chunk.data_offset,
                                chunk.payload_data.end() - chunk.padding);
    }

    accumulate_chunk_statistics(chunk, unigram, bigram, sample_rows,
                                odd_bigram_zero, odd_bigram_ff);

    // 每讀滿 100 個 Chunk 嘗試一次收斂求解
    if (batch_chunks_read >= BATCH_SIZE) {
      batch_chunks_read = 0;
      if (sample_rows > 0) {
        int zero_weight = 10, ff_weight = 4;
        calculate_weights(zero_weight, ff_weight);

        std::array<uint8_t, 32> test_vm1{};
        if (solve_vm1_bigram(unigram, bigram, 50, 300, zero_weight, ff_weight,
                             test_vm1)) {
          KeyResult candidate_res = build_key_result(test_vm1);
          if (test_key_convergence(first_video_packet, candidate_res.key1,
                                   candidate_res.key2)) {
            out_key = candidate_res;
            converged = true;
            std::cout << "  -> [收斂成功] 在第 " << total_chunks_read
                      << " 個 Chunk (累積 " << sample_rows
                      << " 行加密樣本) 成功收斂並驗證金鑰！\n";
            break;
          }
        }
      }
    }
  }

  // 處理未滿 100 Chunk 即抵達 EOF 或最後一批次尚未測試的情況
  if (!converged) {
    if (sample_rows == 0) {
      std::cerr
          << "[Crack Error] 找不到足以進行頻率分析的 @SFV 視訊加密區塊。\n";
      return false;
    }

    int zero_weight = 10, ff_weight = 4;
    calculate_weights(zero_weight, ff_weight);

    std::array<uint8_t, 32> best_vm1{};
    if (!solve_vm1_bigram(unigram, bigram, 50, 300, zero_weight, ff_weight,
                          best_vm1)) {
      std::cerr << "[Crack Error] 束搜尋未找到有效候選金鑰遮罩。\n";
      return false;
    }

    out_key = build_key_result(best_vm1);
    if (!first_video_packet.empty() &&
        test_key_convergence(first_video_packet, out_key.key1, out_key.key2)) {
      converged = true;
      std::cout << "  -> [收斂成功] 在檔案結尾 (共 " << total_chunks_read
                << " 個 Chunk, 累積 " << sample_rows
                << " 行加密樣本) 成功收斂並驗證金鑰！\n";
    } else {
      std::cout << "  -> [提示] 已讀取至檔案結尾 (共 " << total_chunks_read
                << " 個 Chunk)，採用最高分候選金鑰。\n";
    }
  }

  // 若 output_video 為 true，進行解密並串流匯出影片
  if (output_video) {
    UsmKeys keys = generate_usm_keys(out_key.key1, out_key.key2);
    if (!export_file(out_ivf_file, reader, keys)) {
      std::cerr << "[Export Error] 無法寫入解密後的影片檔至: " << out_ivf_file
                << "\n";
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

  // 初始化串流讀取器
  UsmReader reader(usm_file);
  if (!reader.is_open()) {
    std::cerr << "錯誤：無法開啟 USM 檔案或檔案過小: " << usm_file << "\n";
    return 1;
  }

  KeyResult key_result;

  if (explicit_keys) {
    try {
      key_result.key1 = static_cast<uint32_t>(std::stoul(argv[3], nullptr, 16));
      key_result.key2 = static_cast<uint32_t>(std::stoul(argv[4], nullptr, 16));
    } catch (const std::exception &e) {
      std::cerr << "錯誤：key1 / key2 必須為十六進位數字 (" << e.what()
                << ")\n";
      return 1;
    }
    std::cout << "[模式] 使用手動指定的 Key1: 0x" << std::hex << std::uppercase
              << key_result.key1 << ", Key2: 0x" << key_result.key2 << std::dec
              << "\n";

    UsmKeys keys = generate_usm_keys(key_result.key1, key_result.key2);
    if (!export_file(ivf_file, reader, keys)) {
      std::cerr << "錯誤：寫入影片檔案失敗。\n";
      return 1;
    }
    std::cout << "解密並還原影片成功： " << ivf_file << "\n";
  } else {
    bool output_video = (argc >= 3);
    std::cout
        << "[模式] 啟動串流動態收斂金鑰破解演算法 (Batch Beam Search)...\n";

    // 調用核心破解函式
    if (crack_usm_key(reader, output_video, key_result, ivf_file)) {
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
