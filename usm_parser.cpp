#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iosfwd>
#include <iostream>
#include <map>
#include <ostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#endif

// 說明 原bytes -> 00 01 02 03
// BIG -> 00 01 02 03
// LITTLE -> 03 02 01 00
enum class ENDIAN { BIG, LITTLE };

// ------------------------------------------------------------
// 指標版本的多位元組讀取函式。
// 傳入的 ptr 是一個「參照到指標」(reference to pointer)，讀取完成後
// ptr 會自動往前移動 sizeof(uint_type) bytes，這樣呼叫端只要
// 依序呼叫這個函式，就能像用游標一樣往前掃過整塊記憶體，
// 不再需要自己手動維護 offset 變數、也不用每次都重新計算
// data.data() + offset。
// ------------------------------------------------------------
template <typename type>
type ptr_to_type(const uint8_t *&ptr, ENDIAN endian = ENDIAN::BIG) {
  constexpr size_t byteCount = sizeof(type);

  type result = 0;
  if (endian == ENDIAN::BIG) {
    std::memcpy(&result, ptr, byteCount);
  } else if (endian == ENDIAN::LITTLE) {
    for (size_t i = 0; i < sizeof(type); ++i) {
      std::memcpy(&result + i, ptr + sizeof(type) - 1 - i, 1);
    }
  } else {
    throw std::logic_error("未知的endian類別");
  }

  ptr += byteCount; // 讀取完自動前進，模擬「游標」的行為
  return result;
}

// 不移動指標的版本（單純窺視某個位置的值），保留給少數需要
// 「先看但不前進」的情境使用。
template <typename uint_type>
uint_type peek_type(const uint8_t *ptr, ENDIAN endian = ENDIAN::BIG) {
  const uint8_t *tmp = ptr;
  return ptr_to_type<uint_type>(tmp, endian);
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
  uint8_t *data = reinterpret_cast<uint8_t *>(packet.data()) + 0x40;

  for (size_t i = 0x100; i < encrypted_part_size; ++i) {
    data[i] ^= rolling[0x20 + (i % 0x20)];
    rolling[0x20 + (i % 0x20)] = data[i] ^ video_key[0x20 + (i % 0x20)];
  }
  for (size_t i = 0; i < 0x100; ++i) {
    rolling[i % 0x20] ^= data[0x100 + i];
    data[i] ^= rolling[i % 0x20];
  }
}

// 對單一個 audio stream chunk 的 payload 做加/解密（同一操作可逆）。
// 前 0x140 byte 不加密。
void decrypt_audio_packet(std::vector<char> &packet,
                          const std::array<uint8_t, 0x20> &audio_key) {
  if (packet.size() <= 0x140)
    return;
  uint8_t *data = reinterpret_cast<uint8_t *>(packet.data()) + 0x140;
  size_t n = packet.size() - 0x140;
  for (size_t i = 0; i < n; ++i) {
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
// -----------------------------------------------------------------
// 這裡改成用一個往前推進的指標依序讀取每個欄位，
// 而不是像原本一樣每個欄位各自寫死一個 offset 數字，
// 這樣欄位的順序本身就代表了記憶體的排列順序，較不容易寫錯 offset。
// -----------------------------------------------------------------
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

    const uint8_t *ptr = reinterpret_cast<const uint8_t *>(chrs.data());

    unknown_1 = *ptr;
    ++ptr;
    data_offset = *ptr;
    ++ptr;
    padding = ptr_to_type<uint16_t>(ptr);
    channel = *ptr;
    ++ptr;
    unknown_2 = ptr_to_type<uint16_t>(ptr);
    type_raw = *ptr;
    ++ptr;
    frame_time = ptr_to_type<uint32_t>(ptr);
    frame_rate = ptr_to_type<uint32_t>(ptr);
    unknown_3 = ptr_to_type<uint64_t>(ptr);
    // 讀到這裡 ptr 應該剛好落在 chrs.data() + 24 的位置

    if (static_cast<size_t>(padding) > chrs.size() - 24)
      throw std::out_of_range("解析Payload時 padding 大於剩餘資料長度。");

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
    const uint8_t *ptr =
        reinterpret_cast<const uint8_t *>(data.data()) + offset;

    std::memcpy(magic, ptr, 4);
    ptr += 4;
    version = ptr_to_type<uint16_t>(ptr, ENDIAN::LITTLE);
    header_length = ptr_to_type<uint16_t>(ptr, ENDIAN::LITTLE);
    std::memcpy(codec, ptr, 4);
    ptr += 4;
    width = ptr_to_type<uint16_t>(ptr, ENDIAN::LITTLE);
    height = ptr_to_type<uint16_t>(ptr, ENDIAN::LITTLE);
    frame_rate = ptr_to_type<uint32_t>(ptr, ENDIAN::LITTLE);
    time = ptr_to_type<uint32_t>(ptr, ENDIAN::LITTLE);
    frames_number = ptr_to_type<uint32_t>(ptr, ENDIAN::LITTLE);
    unused = ptr_to_type<uint32_t>(ptr, ENDIAN::LITTLE);
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
    const uint8_t *ptr =
        reinterpret_cast<const uint8_t *>(data.data()) + offset;

    size = ptr_to_type<uint32_t>(ptr, ENDIAN::LITTLE);
    if (data.size() < offset + 12 + size) {
      std::ostringstream oss;
      oss << "IVF_frame_data 聲明data長度不足(輸入data.size:" << data.size()
          << ", 聲明size:" << size << ")";
      throw std::out_of_range(oss.str());
    }
    timestamp = ptr_to_type<uint64_t>(ptr, ENDIAN::LITTLE);
    // ptr 現在指向 offset + 12，也就是實際 frame data 的起點
    this->data.assign(reinterpret_cast<const char *>(ptr),
                      reinterpret_cast<const char *>(ptr) + size);
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
    if (data.size() < 32)
      throw std::out_of_range("UTF_Info 資料長度不足");

    const uint8_t *ptr = reinterpret_cast<const uint8_t *>(data.data());

    std::memcpy(magic, ptr, 4);
    ptr += 4;
    payload_size = ptr_to_type<uint32_t>(ptr);
    data2_offset = ptr_to_type<uint32_t>(ptr);
    str_stream_offset = ptr_to_type<uint32_t>(ptr);
    byte_stream_offset = ptr_to_type<uint32_t>(ptr);
    table_name_offset = ptr_to_type<uint32_t>(ptr);
    row_count = ptr_to_type<uint16_t>(ptr);
    row_size_in_data2 = ptr_to_type<uint16_t>(ptr);
    total_cals = ptr_to_type<uint32_t>(ptr);
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

// UTF 表格中每個「欄位描述」是 1 byte flag + 4 byte name_offset，
// 固定佔 5 bytes。這裡改成傳入一個「參照到指標」，建構完後指標會
// 自動前進 5 bytes，呼叫端只要在迴圈裡連續建構這個物件，就能像
// 用讀取游標一樣依序掃過所有欄位描述，不用再手動加 offset += 5。
struct UTF_Data {
  uint8_t flag;
  uint32_t name_offset;

  size_t used_bytes; // in data I
  bool use_dataII;
  UTF_DATA_TYPE data_type;

  UTF_Data(const uint8_t *&ptr) {
    flag = *ptr;
    const uint8_t *name_ptr = ptr + 1;
    name_offset = ptr_to_type<uint32_t>(name_ptr);
    parse_flag(flag, use_dataII, data_type, used_bytes);
    ptr += 5; // 1 byte flag + 4 byte name_offset
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

// 從 vec[pos] 開始讀一個以 \0 結尾的字串。
// 改用指標掃描直到 \0 或到達 vec 尾端為止，避免依賴
// std::string(const char*) 對未受控記憶體做未定義行為的讀取。
std::string char_to_string(std::vector<char> &vec, size_t pos) {
  if (pos >= vec.size())
    return "";
  const char *start = vec.data() + pos;
  const char *end = vec.data() + vec.size();
  const char *p = start;
  while (p < end && *p != '\0')
    ++p;
  return std::string(start, p);
}

// 照著pointer找到\0結尾的字串 (提供給只有指標、沒有vector上下文的呼叫端使用)
std::string char_to_string(const char *ptr, const char *buffer_end) {
  if (ptr == nullptr || ptr >= buffer_end)
    return "";
  const char *p = ptr;
  while (p < buffer_end && *p != '\0')
    ++p;
  return std::string(ptr, p);
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

  // 用指標依序讀取 4 byte 大端序整數，取代原本手動位移運算的寫法
  const uint8_t *size_ptr =
      reinterpret_cast<const uint8_t *>(payload_size_temp);
  chunk.payload_size = ptr_to_type<uint32_t>(size_ptr, ENDIAN::BIG);

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

    // 用一個游標指標依序讀出 frame size 與 timestamp，
    // 取代原本各自帶著不同 offset 呼叫 char_to_uint 的寫法。
    const uint8_t *frame_header_ptr =
        reinterpret_cast<const uint8_t *>(payload.data.data()) + offset;
    uint32_t frame_size =
        ptr_to_type<uint32_t>(frame_header_ptr, ENDIAN::LITTLE);
    uint64_t timestamp =
        ptr_to_type<uint64_t>(frame_header_ptr, ENDIAN::LITTLE);
    // frame_header_ptr 讀完之後正好指向 frame data 開頭 (offset + 12)

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

    // 用指標直接走訪要預覽的資料，而不是每次都透過
    // payload.data[frame_data_offset + i] 做 vector 索引。
    const uint8_t *preview_ptr =
        reinterpret_cast<const uint8_t *>(payload.data.data()) +
        frame_data_offset;
    for (size_t i = 0; i < preview_size; ++i) {
      output << std::hex << std::setw(2) << std::setfill('0')
             << static_cast<unsigned int>(preview_ptr[i]) << " ";
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
  std::string tab = "      ";
  if (payload.data.size() < 8 + 24) { // 至少需要讀到 array_size
    output << tab << "錯誤：@UTF 數據過短，無法讀取表頭。\n";
    return false;
  }

  std::vector<char> &data = payload.data;

  UTF_Info utf = UTF_Info(data);
  if (std::string(utf.magic, 4) != "@UTF") {
    output << tab << "警告：預期Magic: @UTF，但得到 '"
           << std::string(utf.magic, 4) << "' 停止解析。\n";
    return false;
  }
  output << "    @UTF 表格解析：\n";
  const std::vector<std::string> utf_field_labels = {
      "magic id：",
      "payload 大小：",
      "資料II區偏移 (相對於@UTF內容起始)：",
      "字串區偏移 (相對於@UTF內容起始)：",
      "字節流區偏移 (相對於@UTF內容起始)：",
      "表格名稱字串偏移 (相對於字串區起始)：",
      "每行欄位數：",
      "每行於資料II區大小 (bytes)：",
      "總行數：",
      "表格名稱："};
  output << tab << utf_field_labels[0] << std::string(utf.magic, 4) << "\n";
  output << tab << utf_field_labels[1] << utf.payload_size << "\n";
  output << tab << utf_field_labels[2] << utf.data2_offset << "\n";
  output << tab << utf_field_labels[3] << utf.str_stream_offset << "\n";
  output << tab << utf_field_labels[4] << utf.byte_stream_offset << "\n";
  output << tab << utf_field_labels[5] << utf.table_name_offset << "\n";
  output << tab << utf_field_labels[6] << utf.row_count << "\n";
  output << tab << utf_field_labels[7] << utf.row_size_in_data2 << "\n";
  output << tab << utf_field_labels[8] << utf.total_cals << "\n";

  output << tab << utf_field_labels[9]
         << char_to_string(data,
                           8 + utf.str_stream_offset + utf.table_name_offset)
         << "\n";
  tab += "  ";

  // Data I 區的欄位描述表，每個描述固定 5 bytes (1 byte flag + 4 byte
  // name_offset)，從 @UTF 內容起始算起偏移 32 byte 開始。
  // 用一個指標當作游標，依序建構 UTF_Data，每次建構完指標會自動前進，
  // 完全不需要手動維護 offset 變數。
  if (data.size() < 32) {
    output << tab << "錯誤：資料長度不足以讀取欄位描述表。\n";
    return false;
  }
  const uint8_t *field_ptr =
      reinterpret_cast<const uint8_t *>(data.data()) + 8 + 24;
  const uint8_t *dataII_ptr =
      reinterpret_cast<const uint8_t *>(data.data()) + 8 + utf.data2_offset;
  const uint8_t *data_end =
      reinterpret_cast<const uint8_t *>(data.data()) + data.size();

  for (int i = 0; i < utf.row_count; i++) {
    if (field_ptr + 5 > data_end) {
      output << tab << "警告：欄位描述表資料不足，提前停止解析（已解析 " << i
             << " / " << utf.row_count << " 欄位）。\n";
      break;
    }
    UTF_Data utf_data(field_ptr); // 建構後 field_ptr 自動前進 5 bytes

    // 欄位名稱存放在字串區內，位置為 str_stream_offset + name_offset
    // (同樣是相對於 @UTF 內容起始，也就是 payload.data 的第 8 byte)
    std::string field_name =
        char_to_string(data, 8 + utf.str_stream_offset + utf_data.name_offset);

    std::string field_data = "unknown";
    {
      const uint8_t *pointer = utf_data.use_dataII ? dataII_ptr : field_ptr;
      switch (utf_data.data_type) {
      case UTF_DATA_TYPE::CHAR:
        field_data = std::to_string(ptr_to_type<char>(pointer));
        break;
      case UTF_DATA_TYPE::UCHAR:
        field_data = std::to_string(ptr_to_type<unsigned char>(pointer));
        break;
      case UTF_DATA_TYPE::SHORT:
        field_data = std::to_string(ptr_to_type<short>(pointer));
        break;
      case UTF_DATA_TYPE::USHORT:
        field_data = std::to_string(ptr_to_type<unsigned short>(pointer));
        break;
      case UTF_DATA_TYPE::INT:
        field_data = std::to_string(ptr_to_type<int>(pointer));
        break;
      case UTF_DATA_TYPE::UINT:
        field_data = std::to_string(ptr_to_type<unsigned int>(pointer));
        break;
      case UTF_DATA_TYPE::LONG:
        field_data = std::to_string(ptr_to_type<long long>(pointer));
        break;
      case UTF_DATA_TYPE::ULONG:
        field_data = std::to_string(ptr_to_type<unsigned long long>(pointer));
        break;
      case UTF_DATA_TYPE::FLOAT:
        field_data = std::to_string(ptr_to_type<float>(pointer));
        break;
      case UTF_DATA_TYPE::DOUBLE:
        field_data = std::to_string(ptr_to_type<double>(pointer));
        break;
      case UTF_DATA_TYPE::STRING:
      case UTF_DATA_TYPE::BYTE:
        /*未定義*/
        break;
      }
    }

    output << tab << "欄位名 '" << field_name << "'  型別："
           << dataTypeToString(utf_data.data_type) << "  使用資料II："
           << (utf_data.use_dataII ? "是" : "否") << "  資料I佔用大小："
           << utf_data.used_bytes << " bytes\n";
  }
  return true;
}

bool getOutput_payload_data_general(size_t length, ChunkPayload &payload,
                                    std::ostream &output) {

  size_t data_size = payload.data.size();
  size_t display_length = (length > data_size) ? data_size : length;
  output << "  Payload 內容 (前 " << display_length << " / " << data_size
         << " byte)：\n";

  const uint8_t *ptr = reinterpret_cast<const uint8_t *>(payload.data.data());

  // section_end 或 seek
  if (payload.type_raw == 0x02 || payload.type_raw == 0x03) {
    output << "    ";
    for (size_t k = 0; k < display_length; ++k) {
      isprint(ptr[k]) ? output << static_cast<char>(ptr[k])
                      : output << "."; // 非可列印字元用 . 表示
    }
    output << "\n";
  } else { // 其他 stream 數據
    output << "    ";
    for (size_t k = 0; k < display_length; ++k) {
      output << std::hex << std::setw(2) << std::setfill('0')
             << static_cast<unsigned int>(ptr[k]) << " ";
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
    if (i >= static_cast<int>(chunks.size()))
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
      getOutput_payload_data_general(static_cast<size_t>(length), payload,
                                     output);
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

  // 一開始就先提醒使用者：這支程式大量使用指標直接讀取二進位資料，
  // 若輸入的 .usm 檔案本身已損壞或格式不符，很可能造成越界讀取等
  // 未定義行為導致程式崩潰。
  std::cout << "如果程式崩潰 可能是因為未定義行為 請檢查檔案是否已損壞"
            << std::endl;

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
