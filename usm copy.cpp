#include <array>
#include <bitset>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iosfwd>
#include <iostream>
#include <map>
#include <numeric>
#include <ostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#endif

// 設 原bytes -> 00 01 02 03
// BIG -> 00 01 02 03
// LITTLE -> 03 02 01 00
enum class ENDIAN { BIG, LITTLE };

template <typename uint_type>
uint_type char_to_uint(const std::vector<char> &chr, size_t offset,
                       ENDIAN endian = ENDIAN::BIG) {
  static_assert(std::is_unsigned<uint_type>::value, "只允許 unsigned 數字類別");
  constexpr size_t byteCount = sizeof(uint_type);

  if (chr.size() < offset + byteCount) {
    throw std::out_of_range("vector長度不夠:" + std::to_string(chr.size()) +
                            " 取值:" + std::to_string(offset) +
                            " 以及後續需要的長度:" + std::to_string(byteCount));
  }
  uint_type result = 0;
  if (endian == ENDIAN::BIG) {
    for (size_t i = 0; i < byteCount; ++i) {
      result <<= 8;
      result |= static_cast<uint8_t>(chr[offset + i]);
    }
  } else if (endian == ENDIAN::LITTLE) {
    for (size_t i = 0; i < byteCount; ++i) {
      result |= static_cast<uint64_t>(static_cast<uint8_t>(chr[offset + i]))
                << (8 * i);
    }

  } else
    throw std::logic_error("未知的endian類別");

  return result;
}

const size_t CHUNK_HEADER_SIZE = 8;

// ============================================================
// USM 影音串流解密 (CRI Sofdec2)
//
// CRI 的 USM 加密是用 key1(高32位)、key2(低32位) 組成一個 64
// bit 的種子，經過固定的位元運算展開成 0x40 byte 的影像遮罩
// (video key) 與 0x20 byte 的音訊遮罩 (audio key)，
// 再用「滾動 XOR」的方式對每個 stream chunk 的 payload 做加解密。
// 這裡的演算法是公開、被多個開源工具（如 WannaCRI）重新實作過的
// 版本，加解密是同一個對稱操作，用同一組 key 執行一次即可還原。
// ============================================================
struct UsmKeys {
  std::array<uint8_t, 0x40> video_key;
  std::array<uint8_t, 0x20> audio_key;
};

// 由 key1(高32位)、key2(低32位) 組成的 64bit 數字展開出影像/音訊金鑰
UsmKeys generate_usm_keys(uint64_t key_num) {
  uint8_t cipher_key[8];
  for (int i = 0; i < 8; ++i) {
    cipher_key[i] = static_cast<uint8_t>((key_num >> (8 * i)) & 0xFF);
  }

  uint8_t key[0x20];
  key[0x00] = cipher_key[0];
  key[0x01] = cipher_key[1];
  key[0x02] = cipher_key[2];
  key[0x03] = static_cast<uint8_t>(cipher_key[3] - 0x34);
  key[0x04] = static_cast<uint8_t>(cipher_key[4] + 0xF9);
  key[0x05] = cipher_key[5] ^ 0x13;
  key[0x06] = static_cast<uint8_t>(cipher_key[6] + 0x61);
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

// 由 key1(高32位)、key2(低32位) 直接組出 64bit key_num 再展開金鑰
UsmKeys generate_usm_keys(uint32_t key1, uint32_t key2) {
  uint64_t key_num =
      (static_cast<uint64_t>(key1) << 32) | static_cast<uint64_t>(key2);
  return generate_usm_keys(key_num);
}

// 對單一個 video stream chunk 的 payload 做加/解密（同一操作可逆）。
// 前 0x40 byte 是不加密的 header，payload 總長需 >= 0x240 才會真的動到資料。
void decrypt_video_packet(std::vector<char> &packet,
                          const std::array<uint8_t, 0x40> &video_key) {
  if (packet.size() <= 0x40)
    return;
  size_t encrypted_part_size = packet.size() - 0x40;
  if (encrypted_part_size < 0x200)
    return; // 太短，CRI 不會加密

  std::vector<uint8_t> rolling(video_key.begin(), video_key.end());
  uint8_t *data = reinterpret_cast<uint8_t *>(packet.data());

  for (size_t i = 0x100; i < encrypted_part_size; ++i) {
    data[0x40 + i] ^= rolling[0x20 + (i % 0x20)];
    rolling[0x20 + (i % 0x20)] = data[0x40 + i] ^ video_key[0x20 + (i % 0x20)];
  }
  for (size_t i = 0; i < 0x100; ++i) {
    rolling[i % 0x20] ^= data[0x140 + i];
    data[0x40 + i] ^= rolling[i % 0x20];
  }
}

// 對單一個 audio stream chunk 的 payload 做加/解密（同一操作可逆）。
// 前 0x140 byte 不加密。
void decrypt_audio_packet(std::vector<char> &packet,
                          const std::array<uint8_t, 0x20> &audio_key) {
  if (packet.size() <= 0x140)
    return;
  uint8_t *data = reinterpret_cast<uint8_t *>(packet.data());
  for (size_t i = 0x140; i < packet.size(); ++i) {
    data[i] ^= audio_key[i % 0x20];
  }
}

// Chunk 資訊結構體 (與之前相同)
struct ChunkInfo {
  char magic[4];                  // 0~3 magic
  uint32_t payload_size;          // 4~7 payload 大小
  std::vector<char> payload_data; // 8+ payload 的資料
};

// 照著payload前24 byte填寫
struct ChunkPayload {
  uint8_t unknown_1;   // 0 未知1
  uint8_t data_offset; // 1 實際資料開始位置 chunk頭到 data 頭
  uint16_t padding;    // 2~3 payload尾 到chunk尾 的padding
  uint8_t channel;     // 4 通道
  uint16_t unknown_2;  // 5~6 未知2
  uint8_t type_raw;    // 7 種類
  uint32_t frame_time; // 8~11 幀時間
  uint32_t frame_rate; // 12~15幀率
  uint64_t unknown_3;  // 16~23未知3

  std::vector<char> data; // 24+ data

  ChunkPayload(std::vector<char> &chrs) {
    if (chrs.size() < 25)
      throw std::out_of_range("解析Payload時 傳入的vector過小。");
    unknown_1 = (uint8_t)chrs[0];
    data_offset = (uint8_t)chrs[1];
    padding = char_to_uint<uint16_t>(chrs, 2);
    channel = (uint8_t)chrs[4];
    unknown_2 = char_to_uint<uint16_t>(chrs, 5);
    type_raw = (uint8_t)chrs[7];
    frame_time = char_to_uint<uint32_t>(chrs, 8);
    frame_rate = char_to_uint<uint32_t>(chrs, 12);
    unknown_3 = char_to_uint<uint64_t>(chrs, 16);
    data = std::vector<char>(chrs.begin() + 24, chrs.end() - padding);
  }
};

struct IVF_Info {
  /*bytes 0-3  signature: 'DKIF'
    bytes 4-5    version (should be 0)
    bytes 6-7    length of header in bytes
    bytes 8-11   codec FourCC (e.g., 'VP80')
    bytes 12-13  width in pixels
    bytes 14-15  height in pixels
    bytes 16-19  frame rate
    bytes 20-23  time scale
    bytes 24-27  number of frames in file
    bytes 28-31  unused
    */
  char magic[4];
  uint16_t version;
  uint16_t header_length;
  char codec[4];
  uint16_t width;
  uint16_t height;
  uint32_t frame_rate;
  uint32_t time;
  uint32_t frames_number;
  uint32_t unused;
  IVF_Info(const std::vector<char> &data, size_t offset) {
    if (data.size() < offset + 32) {
      throw std::out_of_range("IVF header資料長度不足");
    }
    std::memcpy(magic, &data[offset], 4);
    version = char_to_uint<uint16_t>(data, offset + 4, ENDIAN::LITTLE);
    header_length = char_to_uint<uint16_t>(data, offset + 6, ENDIAN::LITTLE);
    std::memcpy(codec, &data[offset + 8], 4);
    width = char_to_uint<uint16_t>(data, offset + 12, ENDIAN::LITTLE);
    height = char_to_uint<uint16_t>(data, offset + 14, ENDIAN::LITTLE);
    frame_rate = char_to_uint<uint32_t>(data, offset + 16, ENDIAN::LITTLE);
    time = char_to_uint<uint32_t>(data, offset + 20, ENDIAN::LITTLE);
    frames_number = char_to_uint<uint32_t>(data, offset + 24, ENDIAN::LITTLE);
    unused = char_to_uint<uint32_t>(data, offset + 28, ENDIAN::LITTLE);
  }
};

struct IVF_frame_data {
  uint32_t size;      // 0~3 header之後的data大小
  uint64_t timestamp; // 4~11 時間
  std::vector<char> data;
  IVF_frame_data(const std::vector<char> &data, size_t offset) {
    if (data.size() < offset + 8) {
      throw std::out_of_range("IVF_frame_data header資料長度不足");
    }
    size = char_to_uint<uint32_t>(data, offset, ENDIAN::LITTLE);
    if (data.size() < offset + 12 + size) {
      std::ostringstream oss;
      oss << "IVF_frame_data 聲明data長度不足(輸入data.size:" << data.size()
          << ", 聲明size:" << size << ")";
      throw std::out_of_range(oss.str());
    }
    timestamp = char_to_uint<uint64_t>(data, offset + 4, ENDIAN::LITTLE);
    this->data.assign(data.begin() + offset + 12,
                      data.begin() + offset + 12 + size);
  }
};

struct UTF_Info {
  /*
  magic 0~3
  payload size 4~7
  data2 offset 8~11
  string stream offset 12~15
  byte stream offset 16~19
  table offset 20~23
  row count 24~25 欄位
  row size in data2 26~27
  total cals 28~31
  注意 這些offset 是從data開始 而不是header
  */
  // header
  char magic[4];
  uint32_t payload_size;

  // data
  uint32_t data2_offset; //
  uint32_t str_stream_offset;
  uint32_t byte_stream_offset;
  uint32_t table_name_offset;
  uint16_t row_count;
  uint16_t row_size_in_data2;
  uint32_t total_cals;

  // 如果有offset 請先把offset弄好
  UTF_Info(const std::vector<char> &data) {
    std::memcpy(magic, &data, 4);
    payload_size = char_to_uint<uint32_t>(data, 4);
    data2_offset = char_to_uint<uint32_t>(data, 8);
    str_stream_offset = char_to_uint<uint32_t>(data, 12);
    byte_stream_offset = char_to_uint<uint32_t>(data, 16);
    table_name_offset = char_to_uint<uint32_t>(data, 20);
    row_count = char_to_uint<uint16_t>(data, 24);
    row_size_in_data2 = char_to_uint<uint16_t>(data, 26);
    total_cals = char_to_uint<uint32_t>(data, 28);
  }
};

const std::map<uint8_t, std::string> KNOWN_PAYLOAD_TYPES = {
    {0x00, "stream(影/音訊)"},
    {0x01, "header(開頭/CRID)"},
    {0x02, "section_end(標記某個段落結束)"},
    {0x03, "seek(標記查找位置)"}};

enum class UTF_DATA_TYPE {
  CHAR,   // 10000
  UCHAR,  // 10001
  SHORT,  // 10010
  USHORT, // 10011
  INT,    // 10100
  UINT,   // 10101
  LONG,   // 10110
  ULONG,  // 10111
  FLOAT,  // 11000
  DOUBLE, // 11001
  STRING, // 11010 头指针为4B，指向字符串数据
  BYTE    // 11011 头指针与尾指针各4B，指向byte流数据
};

// 分析payload的實際data的標誌
bool parse_flag(const uint8_t &flag, bool &enable_dataII, UTF_DATA_TYPE &type,
                size_t &useBytes) {
  uint8_t h3 = flag & 0b11100000;
  uint8_t l5 = flag & 0b00011111;
  //  啟用數據II 010.....
  // 不啟用數據II 001.....

  if (h3 == 0b01000000) {
    enable_dataII = true;
  } else if (h3 == 0b00100000) {
    enable_dataII = false;
  } else {
    return false;
  }

  const UTF_DATA_TYPE types[] = {
      UTF_DATA_TYPE::CHAR,   UTF_DATA_TYPE::UCHAR,  UTF_DATA_TYPE::SHORT,
      UTF_DATA_TYPE::USHORT, UTF_DATA_TYPE::INT,    UTF_DATA_TYPE::UINT,
      UTF_DATA_TYPE::LONG,   UTF_DATA_TYPE::ULONG,  UTF_DATA_TYPE::FLOAT,
      UTF_DATA_TYPE::DOUBLE, UTF_DATA_TYPE::STRING, UTF_DATA_TYPE::BYTE};
  const size_t uses[] = {1, 1, 2, 2, 4, 4, 8, 8, 4, 8, 0, 0};
  if (l5 >= 0b00010000 && l5 <= 0b00011011) {
    type = types[l5 - 0b00010000];
    useBytes = uses[l5 - 0b00010000];
  } else {
    return false;
  }
  return true;
}

struct UTF_Data {
  uint8_t flag;
  uint32_t name_offset;
  
  size_t used_bytes; // in data I
  bool use_dataII;
  UTF_DATA_TYPE data_type;

  UTF_Data(const std::vector<char> &data, size_t offset) {
    flag = data[offset];
    name_offset = char_to_uint<uint32_t>(data, offset + 1);
    parse_flag(flag, use_dataII, data_type, used_bytes);
  }
};

// 已知的 USM/CRI chunk Magic (與之前相同)
const std::map<std::string, std::string> CHUNK_TYPES = {
    {"CRID", "CRI USM Header (Outer wrapper)"},
    {"@UTF", "UTF Table (Metadata, often contains track info, etc.)"},
    {"@SFV", "Sofdec Video Stream"},
    {"@SFA", "Sofdec Audio Stream"},
    {"@ADX", "ADX Audio Stream"},
    {"@AHX", "AHX Audio Stream"},
    {"@HCA", "HCA Audio Stream"},
    {"@VP9", "VP9 Video Stream"},
    {"H264", "H.264 Video Stream"},
    {"AV01", "AV1 Video Stream"},
    {"OPUS", "Opus Audio Stream"},
    {"@ALP", "Alpha Channel Stream"},
    {"@SUB", "Subtitle Stream"},
    {"INFO", "Information Chunk"},
    {"SEEK", "Seek Table Chunk"}};

std::string dataTypeToString(UTF_DATA_TYPE type) {
  switch (type) {
  case UTF_DATA_TYPE::CHAR:
    return "CHAR";
  case UTF_DATA_TYPE::UCHAR:
    return "UCHAR";
  case UTF_DATA_TYPE::SHORT:
    return "SHORT";
  case UTF_DATA_TYPE::USHORT:
    return "USHORT";
  case UTF_DATA_TYPE::INT:
    return "INT";
  case UTF_DATA_TYPE::UINT:
    return "UINT";
  case UTF_DATA_TYPE::LONG:
    return "LONG";
  case UTF_DATA_TYPE::ULONG:
    return "ULONG";
  case UTF_DATA_TYPE::FLOAT:
    return "FLOAT";
  case UTF_DATA_TYPE::DOUBLE:
    return "DOUBLE";
  case UTF_DATA_TYPE::STRING:
    return "STRING";
  case UTF_DATA_TYPE::BYTE:
    return "BYTE";
  default:
    return "UNKNOWN";
  }
}

std::string char_to_string(std::vector<char> &vec, size_t pos) {
  if (pos >= vec.size())
    return "";
  // 可能會有未定義行為 如果輸入的檔案是壞掉的
  return std::string(&vec[pos]); // 要保證從 pos 開始有 \0 結尾
}

// 嘗試在指定的位移解析一個 Chunk
// 返回 true 如果成功解析，false 如果失敗 (例如，到達檔案末尾或讀取錯誤)
bool parse_one_chunk(std::ifstream &ifs, size_t chunk_offset, ChunkInfo &chunk,
                     std::ostream &error) {
  auto read_bytes = [&](std::streamoff offset, char *buffer,
                        std::streamsize size,
                        const std::string &context) -> bool {
    ifs.seekg(offset);
    if (!ifs.read(buffer, size)) {
      error << "錯誤：在位移 0x" << std::hex << offset << std::dec << " 讀取 "
            << context << " 時";
      if (ifs.eof() && ifs.gcount() < size) {
        error << " 到達檔案結尾。\n";
      } else if (!ifs.eof()) {
        error << " 讀取失敗 (非 EOF)。\n";
      } else {
        error << " 發生未知錯誤。\n";
      }
      return false;
    }
    return true;
  };
  char magic_temp[4] = {0}; // 改為4個字元，與 magic 大小一致
  if (!read_bytes(chunk_offset, magic_temp, 4, "chunk 類型 (magic)"))
    return false;
  std::memcpy(chunk.magic, magic_temp, 4);

  char payload_size_temp[4];
  if (!read_bytes(chunk_offset + 4, payload_size_temp, 4,
                  "Chunk '" + std::string(chunk.magic, 4) +
                      "' 的 Payload 大小"))
    return false;

  chunk.payload_size =
      (static_cast<uint32_t>(static_cast<unsigned char>(payload_size_temp[0]))
       << 24) |
      (static_cast<uint32_t>(static_cast<unsigned char>(payload_size_temp[1]))
       << 16) |
      (static_cast<uint32_t>(static_cast<unsigned char>(payload_size_temp[2]))
       << 8) |
      (static_cast<uint32_t>(static_cast<unsigned char>(payload_size_temp[3])));
  chunk.payload_data.resize(chunk.payload_size);
  if (!read_bytes(
          chunk_offset + 8, chunk.payload_data.data(), chunk.payload_size,
          "Chunk '" + std::string(chunk.magic, 4) + "' 的 Payload 內容"))
    return false;
  return true;
}

bool getOutput_payload_data_for_ivf(ChunkPayload &payload,
                                    std::ostream &output) {
  if (payload.data.size() < 4) {
    output << "      錯誤：IVF 數據過短，無法讀取 Magic。\n";
    return false;
  }

  output << "    IVF 串流詳細解析：\n";
  output << "      payload.data 總大小：" << payload.data.size() << " bytes\n";

  size_t offset = 0;

  // 如果開頭是 DKIF，先解析 IVF header
  if (payload.data.size() >= 32 &&
      std::memcmp(payload.data.data(), "DKIF", 4) == 0) {

    IVF_Info ivf(payload.data, 0);

    output << "      Magic ID：" << std::string(ivf.magic, 4) << "\n";
    output << "      version：" << ivf.version << "\n";
    output << "      IVF header 偏移：0\n";
    output << "      IVF header 大小：" << ivf.header_length << " bytes\n";
    output << "      Codec：" << std::string(ivf.codec, 4) << "\n";
    output << "      解析度 (width x height)：" << ivf.width << " x "
           << ivf.height << "\n";
    output << "      幀率 / 時間基：" << ivf.frame_rate << " / " << ivf.time
           << "\n";
    output << "      宣告總幀數：" << ivf.frames_number << "\n";
    output << "      未使用欄位：" << ivf.unused << "\n";

    if (ivf.header_length == 0) {
      offset = 32;
      output << "      警告：IVF header 宣告大小為 0，改用預設 32 bytes。\n";
    } else {
      offset = ivf.header_length;
    }

    if (offset > payload.data.size()) {
      output << "      錯誤：IVF header 大小超出 payload.data 範圍。\n";
      return false;
    }

  } else {
    output << "      此 payload 沒有 IVF header(DKIF)，直接嘗試解析 frame "
              "packet。\n";
  }

  size_t frame_packet_index = 0;

  // 連續解析 frame packet
  // IVF frame packet:
  // 4 bytes frame size
  // 8 bytes timestamp
  // N bytes frame data
  while (offset < payload.data.size()) {

    // frame header 至少 12 bytes
    if (offset + 12 > payload.data.size()) {
      output << "      錯誤：剩餘 " << (payload.data.size() - offset)
             << " bytes，不足以讀取 12 bytes frame header。\n";
      return false;
    }

    uint32_t frame_size =
        char_to_uint<uint32_t>(payload.data, offset, ENDIAN::LITTLE);

    uint64_t timestamp =
        char_to_uint<uint64_t>(payload.data, offset + 4, ENDIAN::LITTLE);

    size_t frame_data_offset = offset + 12;

    uint64_t packet_end = static_cast<uint64_t>(frame_data_offset) + frame_size;

    output << "      Frame packet #" << (frame_packet_index + 1) << "：\n";
    output << "        Frame 標頭偏移 (於payload.data)：" << offset << "\n";
    output << "        Frame 標頭大小：12 bytes\n";
    output << "        frame size：" << frame_size << " bytes\n";
    output << "        timestamp：" << timestamp << "\n";
    output << "        實際資料偏移：" << frame_data_offset << "\n";
    output << "        packet 總大小："
           << (static_cast<uint64_t>(frame_size) + 12ULL) << " bytes\n";

    if (packet_end > payload.data.size()) {
      output << "        錯誤：frame size 超出 payload.data 剩餘範圍。\n";
      output << "        目前偏移：" << offset << "\n";
      output << "        frame_data_offset：" << frame_data_offset << "\n";
      output << "        frame_size：" << frame_size << "\n";
      output << "        payload.data.size()：" << payload.data.size() << "\n";
      return false;
    }

    // 顯示一點 frame data 前 16 bytes，方便確認
    size_t preview_size = (frame_size < 64) ? frame_size : 64;

    output << "        實際資料前 " << preview_size << " bytes：";

    for (size_t i = 0; i < preview_size; ++i) {
      output << std::hex << std::setw(2) << std::setfill('0')
             << static_cast<unsigned int>(static_cast<unsigned char>(
                    payload.data[frame_data_offset + i]))
             << " ";
    }

    output << std::dec << "\n";

    offset = static_cast<size_t>(packet_end);
    ++frame_packet_index;
  }

  output << "      此 payload 共解析出 " << frame_packet_index
         << " 個 frame packet。\n";

  if (frame_packet_index == 0) {
    output << "      警告：沒有解析到任何 frame packet。\n";
  }

  if (offset != payload.data.size()) {
    output << "      警告：解析結束後仍剩餘 " << (payload.data.size() - offset)
           << " bytes。\n";
  }

  return true;
}

bool getOutput_payload_data_for1(ChunkPayload &payload, std::ostream &output) {
  if (payload.data.size() < 4) {
    output << "      錯誤：@UTF 數據過短，無法讀取 Magic。\n";
    return false;
  }
  if (payload.data.size() < 8) { // @UTF + size
    output << "      錯誤：@UTF 數據過短，無法讀取總大小。\n";
    return false;
  }
  if (payload.data.size() < 8 + 24) { // 至少需要讀到 array_size
    output << "      錯誤：@UTF 數據過短，無法讀取表頭元數據。\n";
    return false;
  }
  UTF_Info utf = UTF_Info(payload.data);
  std::string magic(payload.data.data(), 4);
  if (magic != "@UTF") {
    output << "      警告：預期Magic: @UTF，但得到 '" << magic << "'\n";
    return false;
  }
  output << "    @UTF 表格詳細解析：\n";
  output << "      Magic ID：" << magic << "\n";

  uint32_t internal_utf_payload_size = char_to_uint<uint32_t>(payload.data, 4);
  output << "      @UTF內部Payload大小：" << internal_utf_payload_size
         << " bytes\n";

  // 偏移量定義，從 payload_info.data 的第 8 個字節開始是 UTF header 的數據部分
  size_t utf_header_ofs = 8;
  uint32_t dataII_offset = // dataII 在@UTF header之後的偏移
      char_to_uint<uint32_t>(payload.data, utf_header_ofs + 0);
  uint32_t string_offset = // string stream 在@UTF header之後的偏移
      char_to_uint<uint32_t>(payload.data, utf_header_ofs + 4);
  uint32_t byte_stream_offset = // byte stream 在@UTF header之後的偏移
      char_to_uint<uint32_t>(payload.data, utf_header_ofs + 8);
  uint32_t table_name_offset = // UTF表 在@UTF header之後的偏移
      char_to_uint<uint32_t>(payload.data, utf_header_ofs + 12);
  uint16_t columns_per_row = // 每行有多少欄位
      char_to_uint<uint16_t>(payload.data, utf_header_ofs + 16);
  uint16_t row_size_in_dataII = // 每行用了dataII多少資料 (不知道意義在哪)
      char_to_uint<uint16_t>(payload.data, utf_header_ofs + 18);
  uint32_t total_rows = // 總共有幾行 (不知道什麼意思)
      char_to_uint<uint32_t>(payload.data, utf_header_ofs + 20);

  const std::vector<std::string> utf_field_labels = {
      "資料II區偏移 (相對於@UTF內容起始)：",
      "字串區偏移 (相對於@UTF內容起始)：",
      "字節流區偏移 (相對於@UTF內容起始)：",
      "表格名稱字串偏移 (相對於字串區起始)：",
      "每行欄位數：",
      "每行於資料II區大小 (bytes)：",
      "總行數："};

  output << "      " << utf_field_labels[0] << dataII_offset << "\n";
  output << "      " << utf_field_labels[1] << string_offset << "\n";
  output << "      " << utf_field_labels[2] << byte_stream_offset << "\n";
  output << "      " << utf_field_labels[3] << table_name_offset << "\n";
  output << "      " << utf_field_labels[4] << columns_per_row << "\n";
  output << "      " << utf_field_labels[5] << row_size_in_dataII << "\n";
  output << "      " << utf_field_labels[6] << total_rows << "\n";

  // 定義各數據區域的真實起始偏移 (相對於 payload_info.data[0])

  // 24 == 各種標記總和需要的byte
  size_t region_start_dataI = utf_header_ofs + 24;
  size_t region_start_dataII = utf_header_ofs + dataII_offset;
  size_t region_start_string_data = utf_header_ofs + string_offset;
  size_t region_start_byte_stream_data = utf_header_ofs + byte_stream_offset;

  // 表格名稱
  if (region_start_string_data + table_name_offset < payload.data.size()) {
    std::string table_name_str = char_to_string(
        payload.data, region_start_string_data + table_name_offset);
    output << "      表格名稱：" << table_name_str << "\n";
  }
  output << "      欄位數據：\n";

  // 目前指向的數據 從@UTF頭開始 的偏移
  size_t currRow_dataOfs = region_start_dataI;
  size_t dataII_current_usage_offset = 0; // 用於追蹤在 Data II 中消耗的數據

  for (uint32_t row = 0 /*行數*/; row < total_rows; ++row) {
    output << "        第 " << (row + 1) << " 行：\n";
    for (uint16_t col = 0 /*欄位*/; col < columns_per_row; ++col) {
      if (currRow_dataOfs >= region_start_dataII) {
        output << "          警告：Data I 偏移 (" << currRow_dataOfs
               << ") 已達到或超過 Data II 起始 (" << region_start_dataII
               << ")，提前結束行解析。\n";
        return true;
      }
      if (currRow_dataOfs + 1 > payload.data.size()) { // 至少需要讀 flag
        output << "          錯誤：數據不足以讀取第 " << col + 1
               << " 欄的標誌位。\n";
        return true;
      }
      if (currRow_dataOfs + 1 + 4 > payload.data.size()) { // flag + title_ptr
        output << "          錯誤：數據不足以讀取第 " << col + 1
               << " 欄的標題指針。\n";
        return true;
      }
      // 資料標誌
      uint8_t flag = payload.data[currRow_dataOfs];
      // 資料名稱offset(相對於字串的<NULL>頭)
      uint32_t data_title_name_offset =
          char_to_uint<uint32_t>(payload.data, currRow_dataOfs + 1);
      size_t bytes_in_dataI_storge = 0; // 此欄位在 Data I 中佔用的本地數據大小
      bool use_dataII_storage;          // 是否使用dataII儲存資料
      UTF_DATA_TYPE data_type;          // 資料型別

      if (!parse_flag(flag, use_dataII_storage, data_type,
                      bytes_in_dataI_storge)) {
        output << "          錯誤：解析第 " << col + 1
               << " 欄標誌位失敗 (flag: " << std::bitset<8>(flag) << ")"
               << " 目前偏移：" << currRow_dataOfs << "\n";
        return true;
      }

      std::string column_title_str = "未知欄位";
      if (region_start_string_data + data_title_name_offset <
          payload.data.size()) {
        column_title_str = char_to_string(
            payload.data, region_start_string_data + data_title_name_offset);
      }

      output << "          欄位名 '" << column_title_str
             << "' 類型: " << dataTypeToString(data_type)
             << ", 使用DataII: " << (use_dataII_storage ? "是" : "否")
             << ", 儲存大小: " << bytes_in_dataI_storge << "B, 內容: ";

      // 此欄位的消耗量 預設 flag + title_ptr
      size_t consumed_in_data_I_for_this_column = 1 + 4;
      if (use_dataII_storage) {
        // 標記目前dataII用到哪裡了 從@UTF頭開始
        size_t data_offset_in_dataII =
            region_start_dataII + dataII_current_usage_offset;

        if (data_type == UTF_DATA_TYPE::STRING) {
          uint32_t string_ptr =
              char_to_uint<uint32_t>(payload.data, data_offset_in_dataII);
          output << char_to_string(payload.data,
                                   region_start_string_data + string_ptr);
          dataII_current_usage_offset += 4;
          // 根據CRI spec，通常字串用指針
        } else if (data_type ==
                   UTF_DATA_TYPE::BYTE) { // Byte stream in Data II?
          output << " (DataII 中的byte stream，處理方式待確認)";
        } else { // 數值類型
          if (data_offset_in_dataII + bytes_in_dataI_storge >
                  payload.data.size() ||
              data_offset_in_dataII + bytes_in_dataI_storge >
                  region_start_string_data) { // 避免越界到string區
            output << "錯誤：讀取DataII數據時越界。";
          } else {
            size_t number = std::accumulate(
                payload.data.begin() + data_offset_in_dataII,
                payload.data.begin() + data_offset_in_dataII +
                    bytes_in_dataI_storge,
                0ULL, [](size_t acc, char byte) {
                  return (acc << 8) | static_cast<unsigned char>(byte);
                });
            output << std::dec << number;
          }
        }
        // 更新 Data II 已用偏移
        // Data I 中此欄位不佔用額外本地數據空間
        dataII_current_usage_offset += bytes_in_dataI_storge;
      } else {
        // 數據儲存在 Data I 本地 (flag + title_ptr 後面的字節)
        size_t local_data_start_in_data_I =
            currRow_dataOfs + consumed_in_data_I_for_this_column;
        if (data_type == UTF_DATA_TYPE::STRING) {
          if (local_data_start_in_data_I + 4 >
              payload.data.size()) { // 指針本身需要4B
            output << "錯誤：讀取字串指針時越界。";
          } else {
            uint32_t str_actual_offset = char_to_uint<uint32_t>(
                payload.data, local_data_start_in_data_I);
            if (region_start_string_data + str_actual_offset <
                payload.data.size()) {
              output << "\""
                     << char_to_string(payload.data, region_start_string_data +
                                                         str_actual_offset)
                     << "\"";
            } else {
              output << "錯誤：字串指針越界。";
            }
          }
          consumed_in_data_I_for_this_column += 4; // 字串指針佔4B
        } else if (data_type == UTF_DATA_TYPE::BYTE) {
          if (local_data_start_in_data_I + 8 >
              payload.data.size()) { // 頭尾指針共8B
            output << "錯誤：讀取字節流指針時越界。";
          } else {
            uint32_t byte_start_ptr = char_to_uint<uint32_t>(
                payload.data, local_data_start_in_data_I);
            uint32_t byte_end_ptr = char_to_uint<uint32_t>(
                payload.data, local_data_start_in_data_I + 4);
            output << "[字節流：從 " << byte_start_ptr << " 到 " << byte_end_ptr
                   << " (於字節流區)] ";
            // 實際數據在 byte_stream_data_region_start + byte_start_ptr
            // 可以選擇性地打印部分字節
          }
          consumed_in_data_I_for_this_column += 8; // 字節流指針佔8B
        } else {                                   // 數值類型，直接存儲
          if (local_data_start_in_data_I + bytes_in_dataI_storge >
              payload.data.size()) {
            output << "錯誤：讀取本地數據時越界。";
          } else {
            size_t number = std::accumulate(
                payload.data.begin() + local_data_start_in_data_I,
                payload.data.begin() + local_data_start_in_data_I +
                    bytes_in_dataI_storge,
                0ULL, [](size_t acc, char byte) {
                  return (acc << 8) | static_cast<unsigned char>(byte);
                });
            output << std::dec << number;
          }
          consumed_in_data_I_for_this_column += bytes_in_dataI_storge;
        }
      }
      output << std::dec << "\n";
      // 更新 Data I 中的偏移到下一個欄位
      currRow_dataOfs += consumed_in_data_I_for_this_column;
    }
  }
  return true;
}

bool getOutput_payload_data_general(size_t length, ChunkPayload &payload,
                                    std::ostream &output) {

  size_t data_size = payload.data.size();
  size_t display_length =
      (length < 0 || static_cast<size_t>(length) > data_size)
          ? data_size
          : static_cast<size_t>(length);
  output << "  Payload 內容 (前 " << display_length << " / " << data_size
         << " byte)：\n";
  // section_end 或 seek
  if (payload.type_raw == 0x02 || payload.type_raw == 0x03) {
    output << "    ";
    for (size_t k = 0; k < display_length; ++k) {
      isprint(static_cast<unsigned char>(payload.data[k]))
          ? output << payload.data[k]
          : output << "."; // 非可列印字元用 . 表示
    }
    output << "\n";
  } else { // 其他 stream 數據
    output << "    ";
    for (size_t k = 0; k < display_length; ++k) {
      output << std::hex << std::setw(2) << std::setfill('0')
             << static_cast<unsigned int>(
                    static_cast<unsigned char>(payload.data[k]))
             << " ";
      if ((k + 1) % 16 == 0 && k + 1 < display_length)
        output << std::endl << "    "; // 每16字節換行
    }
    output << std::dec << "\n";
  }
  return true;
}

std::vector<ChunkInfo> parse_chunks(const std::string &filepath,
                                    std::ostream &error) {
  std::ifstream file(filepath, std::ios::binary | std::ios::ate);
  if (!file.is_open()) {
    error << "錯誤：無法打開檔案 '" << filepath << "'\n";
    return {};
  }

  std::streamsize total_file_size_ss = file.tellg();
  if (total_file_size_ss == -1) {
    error << "錯誤：無法獲取檔案大小 '" << filepath << "'\n";
    file.close();
    return {};
  } else if (total_file_size_ss == 0) {
    error << "資訊：檔案 '" << filepath << "' 為空。\n";
    file.close();
    return {};
  }
  if (total_file_size_ss < 8) { // 檔案甚至不夠一個 chunk 的 header
    error << "警告：檔案過小 (" << total_file_size_ss
          << " bytes)，不足以包含一個完整的 Chunk Header (8 bytes)。"
          << "\n";
    return {};
  }
  // 檔案大小
  uint64_t total_file_size = static_cast<uint64_t>(total_file_size_ss);

  std::vector<ChunkInfo> chunks; // 儲存所有解析過的chunk
  uint64_t current_offset = 0;   // 目前解析到哪

  while (current_offset < total_file_size) {
    // 如果剩下的byte不夠 跳出循環
    if (current_offset + CHUNK_HEADER_SIZE >= total_file_size) {
      break;
    }
    ChunkInfo chunk;
    // 如果解析失敗 直接跳出
    if (!parse_one_chunk(file, current_offset, chunk, error))
      break;

    // 注意 payload 大小為 0 的情況
    if (chunk.payload_size == 0) {
      error << "注意：Chunk '" << std::string(chunk.magic, 4)
            << "' 聲明 Payload 大小為 0。\n";
    }

    chunks.push_back(chunk); // 將解析完成的chunk放進chunks內
    // 下一個chunk的起始位置
    current_offset += chunk.payload_size + CHUNK_HEADER_SIZE;

    // 邊界檢查：Chunk 是否聲稱其結尾超出了檔案實際大小
    if (current_offset > total_file_size) {
      error << "警告：Chunk '" << std::string(chunk.magic, 4)
            << "' 的計算大小 (" << chunk.payload_size + CHUNK_HEADER_SIZE
            << ") 將使其總結尾 (0x" << std::hex << current_offset << std::dec
            << ") 超出檔案實際大小 (0x" << std::hex << total_file_size
            << std::dec << ")。可能檔案損壞或已到結尾的填充數據。\n";
      break;
    }
  }

  if (chunks.empty()) {
    // 如果檔案不為空但沒有解析到chunk，上面的警告（如檔案過小）可能已經給出
    // 如果檔案大於8字節但仍未解析到，這裡可以再加一個通用提示
    if (total_file_size >= 8) {
      error << "未能解析出任何 Chunk 結構，儘管檔案大小足夠。\n";
    } // 其他關於檔案大小的問題 在開頭就已偵測過
    file.close();
    return {};
  }
  file.close();
  return chunks;
}
void getOutput_Chunks(std::string filepath, std::ostream &output, int length,
                      int start_chunk, int end_chunk) {
  std::vector<ChunkInfo> chunks = parse_chunks(filepath, output);
  output << "--- USM 檔案分析結果 ---\n";
  for (int i = start_chunk; i <= end_chunk; i++) {
    if (i >= chunks.size())
      break;                      // 額外保護
    ChunkInfo &chunk = chunks[i]; // 使用引用避免複製
    ChunkPayload payload(chunk.payload_data);

    output << std::dec << "--- Chunk #"
           << std::setw(std::to_string(chunks.size()).length())
           << std::setfill('0') << (i + 1) << " ---\n";
    output << "  Chunk 類型 (Magic)：" << std::string(chunk.magic, 4) << "\n";
    output << "  Payload 資訊：\n";
    output << "    原始類型ID：" << static_cast<int>(payload.type_raw) << " ("
           << (KNOWN_PAYLOAD_TYPES.count(payload.type_raw)
                   ? KNOWN_PAYLOAD_TYPES.at(payload.type_raw)
                   : "unknown (" +
                         std::to_string(static_cast<int>(payload.type_raw)) +
                         ")")
           << ")\n";
    output << "    內容數據偏移 (於Payload內)："
           << static_cast<int>(payload.data_offset) << " bytes\n";
    output << "    區塊結尾填充大小：" << payload.padding << " bytes"
           << "\n";
    output << "    通道號：" << static_cast<int>(payload.channel) << "\n";
    output << "    幀時間/計數：" << payload.frame_time << "\n";
    output << "    幀率：" << payload.frame_rate << "\n";

    if ((payload.type_raw == 0x01 || payload.type_raw == 0x03)) {
      getOutput_payload_data_for1(payload, output);
    } else if (payload.type_raw == 0x00) {
      getOutput_payload_data_for_ivf(payload, output);
    } else {
      getOutput_payload_data_general(length, payload, output);
    }
    output << "--- End of Chunk #" << (i + 1) << " ---" << std::endl << "\n";
  }
}

// 將 USM 中所有 type_raw==0 (stream) 的 payload 依序取出並寫入輸出檔。
// 第一個 stream chunk 的 payload 本身就是「32 byte DKIF header + 第一個
// frame packet」，之後每個 stream chunk 的 payload 都是單純的
// 「12 byte frame header(size+timestamp) + frame data」。
// 因此只要把 type_raw==0 的 payload.data 依序原樣接在一起，
// 就會自動組成一個合法的 .ivf 檔案，不需要另外手動寫 header。
void outputFile_IVF(std::string in_file, std::ostream &output,
                    std::ofstream &out_file, bool decrypt = false,
                    const UsmKeys *keys = nullptr) {
  std::vector<ChunkInfo> chunks = parse_chunks(in_file, output);

  bool wrote_header = false;
  size_t frame_count = 0;

  for (auto &chunk : chunks) {
    ChunkPayload payload(chunk.payload_data);
    if (payload.type_raw != 0)
      continue; // 只要 stream(影/音訊) payload

    // 若有提供 key1/key2，先把這個 chunk 的原始資料解密回來，
    // 前 0x40 byte(含 DKIF/IVF frame header)本來就不加密，
    // 所以不管有沒有解密都不影響 has_dkif 的判斷。
    if (decrypt && keys != nullptr) {
      decrypt_video_packet(payload.data, keys->video_key);
    }

    bool has_dkif = payload.data.size() >= 32 &&
                    std::memcmp(payload.data.data(), "DKIF", 4) == 0;

    if (!wrote_header) {
      // 第一個 stream chunk：必須含 DKIF header，否則沒有辦法知道
      // 寬高/幀率/codec，直接放棄。
      if (!has_dkif) {
        output << "錯誤：找不到帶有 DKIF header 的第一個 stream chunk，"
                  "無法建立 IVF 檔頭。\n";
        return;
      }
      out_file.write(payload.data.data(),
                     static_cast<std::streamsize>(payload.data.size()));
      wrote_header = true;
      frame_count++; // header 之後緊接著第一個 frame packet
    } else {
      // 後續 chunk 理論上不應該再帶 DKIF header，若有則跳過(理論上不會發生)
      const char *p = payload.data.data();
      size_t sz = payload.data.size();
      if (has_dkif) {
        p += 32;
        sz -= 32;
      }
      out_file.write(p, static_cast<std::streamsize>(sz));
      frame_count++;
    }
  }

  output << "IVF 匯出完成，共寫入 " << frame_count << " 個 frame。\n";
}
int main(int argc, char *argv[]) {
#ifdef _WIN32
  SetConsoleOutputCP(CP_UTF8);
#endif

  std::string usm_file_path;
  std::string output_file_path = "usm_analysis_log.txt"; // 預設輸出檔案名
  std::string ivf_file_path;                             // 選用：輸出 .ivf
  bool has_key = false;
  uint32_t key1 = 0, key2 = 0;

  auto parse_hex_u32 = [](const std::string &s) -> uint32_t {
    return static_cast<uint32_t>(std::stoul(s, nullptr, 16));
  };

  if (argc == 3) {
    usm_file_path = argv[1];
    output_file_path = argv[2];
  } else if (argc == 4) {
    usm_file_path = argv[1];
    output_file_path = argv[2];
    ivf_file_path = argv[3];
  } else if (argc == 6) {
    usm_file_path = argv[1];
    output_file_path = argv[2];
    ivf_file_path = argv[3];
    try {
      key1 = parse_hex_u32(argv[4]);
      key2 = parse_hex_u32(argv[5]);
      has_key = true;
    } catch (const std::exception &e) {
      std::cerr << "錯誤：key1/key2 必須是16進位數字（可加或不加 0x 前綴）："
                << e.what() << "\n";
      return 1;
    }
  } else {
    std::cerr << "請用以下方式使用此程式：\n"
              << "  分析文字紀錄：.\\XXX.exe 輸入檔案.usm 輸出檔案.txt\n"
              << "  同時匯出IVF：.\\XXX.exe 輸入檔案.usm 輸出檔案.txt "
                 "輸出檔案.ivf\n"
              << "  匯出IVF並解密影片：.\\XXX.exe 輸入檔案.usm 輸出檔案.txt "
                 "輸出檔案.ivf key1(hex) key2(hex)\n";
    return 1;
  }

  std::ofstream log_file(output_file_path);
  if (!log_file.is_open()) {
    std::cerr << "錯誤：無法打開日誌檔案 '" << output_file_path
              << "' 。分析結果將輸出到控制台。" << std::endl;
    if (!usm_file_path.empty()) {
      getOutput_Chunks(usm_file_path, std::cout, 256, 0, 20);
    }
    return 1;
  }
  std::cout << "分析結果正在寫入檔案: " << output_file_path << "\n";
  if (!usm_file_path.empty()) {
    getOutput_Chunks(usm_file_path, log_file, 256, 0, 120);
  }

  if (!ivf_file_path.empty()) {
    std::ofstream ivf_file(ivf_file_path, std::ios::binary);
    if (!ivf_file.is_open()) {
      std::cerr << "錯誤：無法打開IVF輸出檔案 '" << ivf_file_path << "'\n";
    } else {
      if (has_key) {
        UsmKeys keys = generate_usm_keys(key1, key2);
        std::cout << "已提供 key1/key2，將對影片資料進行解密。\n";
        outputFile_IVF(usm_file_path, log_file, ivf_file, true, &keys);
      } else {
        outputFile_IVF(usm_file_path, log_file, ivf_file);
      }
      ivf_file.close();
      std::cout << "IVF 已輸出到: " << ivf_file_path << "\n";
    }
  }

  log_file.close();
  std::cout << "分析完成，結果已保存到: " << output_file_path << "\n";

  return 0;
}