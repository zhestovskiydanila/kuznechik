#ifndef _KUZNECHIK_HPP
#define _KUZNECHIK_HPP

#include <array>
#include <cstdint>
#include <ctime>
#include <immintrin.h>
#include <random>
#include <vector>
#include <log.h>
#include <sys/types.h>
#include <pwd.h>

static const char* module_name = "kuznechik-mac";
static constexpr std::size_t BUFF_SIZE = (1 << 14);

struct GFTables {
  static constexpr uint8_t GPOLY = 0xC3;
  std::array<uint8_t, 256> exp{};
  std::array<uint8_t, 256> log{};

  constexpr GFTables() : exp{}, log{} {
    uint8_t x = 1;
    for (int i = 0; i < 255; ++i) {
      exp[i] = x;
      log[x] = i;
      x = galois_mult(x, 2);
    }
  }

private:
  static constexpr uint8_t galois_mult(uint8_t a, uint8_t b) {
    uint8_t c = 0;
    while (b) {
      if (b & 1)
        c ^= a;
      a = (a << 1) ^ (a & 0x80 ? GPOLY : 0x00);
      b >>= 1;
    }
    return c;
  }
};

class Kuznechik {
public:
  static const std::size_t BLOCK_SIZE = 16;
  static const std::size_t KEY_SIZE = 32;
  static const uint8_t B128 = 0x87;
  static const uint8_t GPOLY = 0xC3;
  static const uint8_t PADDING_CONST = 0x80;
  static const std::size_t ROUNDS = 10;

  using block_t = std::array<uint8_t, BLOCK_SIZE>;
  using key_t = std::array<uint8_t, KEY_SIZE>;

  Kuznechik();

  explicit Kuznechik(key_t &mkey);

  ~Kuznechik();

  void authenticate_message(block_t &msg);
  block_t process_sequence(const char &filename);
  block_t process_sequence(std::vector<uint8_t> &filebuf);

private:
  alignas(16) key_t master_key;
  alignas(16) std::array<block_t, ROUNDS> round_key;
  alignas(16) std::array<block_t, 2> MAC_key;

  static constexpr std::array<uint8_t, 256> SBOX = {
      0xFC, 0xEE, 0xDD, 0x11, 0xCF, 0x6E, 0x31, 0x16, 0xFB, 0xC4, 0xFA, 0xDA,
      0x23, 0xC5, 0x04, 0x4D, 0xE9, 0x77, 0xF0, 0xDB, 0x93, 0x2E, 0x99, 0xBA,
      0x17, 0x36, 0xF1, 0xBB, 0x14, 0xCD, 0x5F, 0xC1, 0xF9, 0x18, 0x65, 0x5A,
      0xE2, 0x5C, 0xEF, 0x21, 0x81, 0x1C, 0x3C, 0x42, 0x8B, 0x01, 0x8E, 0x4F,
      0x05, 0x84, 0x02, 0xAE, 0xE3, 0x6A, 0x8F, 0xA0, 0x06, 0x0B, 0xED, 0x98,
      0x7F, 0xD4, 0xD3, 0x1F, 0xEB, 0x34, 0x2C, 0x51, 0xEA, 0xC8, 0x48, 0xAB,
      0xF2, 0x2A, 0x68, 0xA2, 0xFD, 0x3A, 0xCE, 0xCC, 0xB5, 0x70, 0x0E, 0x56,
      0x08, 0x0C, 0x76, 0x12, 0xBF, 0x72, 0x13, 0x47, 0x9C, 0xB7, 0x5D, 0x87,
      0x15, 0xA1, 0x96, 0x29, 0x10, 0x7B, 0x9A, 0xC7, 0xF3, 0x91, 0x78, 0x6F,
      0x9D, 0x9E, 0xB2, 0xB1, 0x32, 0x75, 0x19, 0x3D, 0xFF, 0x35, 0x8A, 0x7E,
      0x6D, 0x54, 0xC6, 0x80, 0xC3, 0xBD, 0x0D, 0x57, 0xDF, 0xF5, 0x24, 0xA9,
      0x3E, 0xA8, 0x43, 0xC9, 0xD7, 0x79, 0xD6, 0xF6, 0x7C, 0x22, 0xB9, 0x03,
      0xE0, 0x0F, 0xEC, 0xDE, 0x7A, 0x94, 0xB0, 0xBC, 0xDC, 0xE8, 0x28, 0x50,
      0x4E, 0x33, 0x0A, 0x4A, 0xA7, 0x97, 0x60, 0x73, 0x1E, 0x00, 0x62, 0x44,
      0x1A, 0xB8, 0x38, 0x82, 0x64, 0x9F, 0x26, 0x41, 0xAD, 0x45, 0x46, 0x92,
      0x27, 0x5E, 0x55, 0x2F, 0x8C, 0xA3, 0xA5, 0x7D, 0x69, 0xD5, 0x95, 0x3B,
      0x07, 0x58, 0xB3, 0x40, 0x86, 0xAC, 0x1D, 0xF7, 0x30, 0x37, 0x6B, 0xE4,
      0x88, 0xD9, 0xE7, 0x89, 0xE1, 0x1B, 0x83, 0x49, 0x4C, 0x3F, 0xF8, 0xFE,
      0x8D, 0x53, 0xAA, 0x90, 0xCA, 0xD8, 0x85, 0x61, 0x20, 0x71, 0x67, 0xA4,
      0x2D, 0x2B, 0x09, 0x5B, 0xCB, 0x9B, 0x25, 0xD0, 0xBE, 0xE5, 0x6C, 0x52,
      0x59, 0xA6, 0x74, 0xD2, 0xE6, 0xF4, 0xB4, 0xC0, 0xD1, 0x66, 0xAF, 0xC2,
      0x39, 0x4B, 0x63, 0xB6};

  static constexpr std::array<uint8_t, 16> linear_consts = {
      148, 32, 133, 16, 194, 192, 1, 251, 1, 192, 194, 16, 133, 32, 148, 1};

  static constexpr GFTables gf_tables{};

  alignas(16) block_t MAC;

  static constexpr uint8_t gmult_fast(uint8_t a, uint8_t b) {
    if (a == 0 || b == 0) {
      return 0;
    }
    uint16_t sum = gf_tables.log[a] + gf_tables.log[b];
    return sum >= 255 ? gf_tables.exp[sum - 255] : gf_tables.exp[sum];
  }

  static constexpr void func_S(block_t &msg) {
    for (int i = 0; i < BLOCK_SIZE; ++i) {
      msg[i] = SBOX[msg[i]];
    }
  }

  static constexpr void func_R(block_t &msg) {
    uint8_t new_byte = 0;
    for (int i = 0; i < 16; ++i) {
      new_byte ^= gmult_fast(msg[i], linear_consts[i]);
    }
    for (int i = 15; i > 0; --i) {
      msg[i] = msg[i - 1];
    }
    msg[0] = new_byte;
  }

  static constexpr void func_L(block_t &msg) {
    for (int i = 0; i < 16; ++i) {
      func_R(msg);
    }
  }

  static inline void func_L_fast(block_t &msg) {
    __m128i acc = _mm_setzero_si128();

    const uint8_t *m = reinterpret_cast<uint8_t *>(msg.data());

    acc = _mm_xor_si128(acc,
                        *reinterpret_cast<const __m128i *>(L[0][m[0]].data()));
    acc = _mm_xor_si128(acc,
                        *reinterpret_cast<const __m128i *>(L[1][m[1]].data()));
    acc = _mm_xor_si128(acc,
                        *reinterpret_cast<const __m128i *>(L[2][m[2]].data()));
    acc = _mm_xor_si128(acc,
                        *reinterpret_cast<const __m128i *>(L[3][m[3]].data()));
    acc = _mm_xor_si128(acc,
                        *reinterpret_cast<const __m128i *>(L[4][m[4]].data()));
    acc = _mm_xor_si128(acc,
                        *reinterpret_cast<const __m128i *>(L[5][m[5]].data()));
    acc = _mm_xor_si128(acc,
                        *reinterpret_cast<const __m128i *>(L[6][m[6]].data()));
    acc = _mm_xor_si128(acc,
                        *reinterpret_cast<const __m128i *>(L[7][m[7]].data()));
    acc = _mm_xor_si128(acc,
                        *reinterpret_cast<const __m128i *>(L[8][m[8]].data()));
    acc = _mm_xor_si128(acc,
                        *reinterpret_cast<const __m128i *>(L[9][m[9]].data()));
    acc = _mm_xor_si128(
        acc, *reinterpret_cast<const __m128i *>(L[10][m[10]].data()));
    acc = _mm_xor_si128(
        acc, *reinterpret_cast<const __m128i *>(L[11][m[11]].data()));
    acc = _mm_xor_si128(
        acc, *reinterpret_cast<const __m128i *>(L[12][m[12]].data()));
    acc = _mm_xor_si128(
        acc, *reinterpret_cast<const __m128i *>(L[13][m[13]].data()));
    acc = _mm_xor_si128(
        acc, *reinterpret_cast<const __m128i *>(L[14][m[14]].data()));
    acc = _mm_xor_si128(
        acc, *reinterpret_cast<const __m128i *>(L[15][m[15]].data()));

    _mm_storeu_si128(reinterpret_cast<__m128i *>(msg.data()), acc);
  }

  alignas(16) inline static const auto iter_consts = []() {
    std::array<block_t, 32> consts{};
    for (int i = 0; i < 32; ++i) {
      block_t iter_const{};
      iter_const[15] = static_cast<uint8_t>(i + 1);
      func_L(iter_const);
      consts[i] = iter_const;
    }
    return consts;
  }();

  static_assert(iter_consts.size() == 32);

  alignas(16) inline static const auto L = []() {
    std::array<std::array<block_t, 256>, 16> L{};
    for (int i = 0; i < 16; ++i) {
      for (int x = 0; x < 256; x++) {
        block_t tmp{};
        tmp[i] = (uint8_t)x;
        func_L(tmp);
        L[i][x] = tmp;
      }
    }
    return L;
  }();

  alignas(16) inline static const auto SL = []() {
    std::array<std::array<block_t, 256>, 16> SL{};
    for (int i = 0; i < 16; ++i) {
      for (int x = 0; x < 256; x++) {
        uint8_t s = SBOX[x];
        SL[i][x] = L[i][s];
      }
    }
    return SL;
  }();

  inline static void func_SL_fast(block_t &msg) {
    __m128i acc = _mm_setzero_si128();
    const uint8_t *m = reinterpret_cast<uint8_t *>(msg.data());

    acc = _mm_xor_si128(acc,
                        *reinterpret_cast<const __m128i *>(SL[0][m[0]].data()));
    acc = _mm_xor_si128(acc,
                        *reinterpret_cast<const __m128i *>(SL[1][m[0]].data()));
    acc = _mm_xor_si128(acc,
                        *reinterpret_cast<const __m128i *>(SL[2][m[0]].data()));
    acc = _mm_xor_si128(acc,
                        *reinterpret_cast<const __m128i *>(SL[3][m[0]].data()));
    acc = _mm_xor_si128(acc,
                        *reinterpret_cast<const __m128i *>(SL[4][m[0]].data()));
    acc = _mm_xor_si128(acc,
                        *reinterpret_cast<const __m128i *>(SL[5][m[0]].data()));
    acc = _mm_xor_si128(acc,
                        *reinterpret_cast<const __m128i *>(SL[6][m[0]].data()));
    acc = _mm_xor_si128(acc,
                        *reinterpret_cast<const __m128i *>(SL[7][m[0]].data()));
    acc = _mm_xor_si128(acc,
                        *reinterpret_cast<const __m128i *>(SL[8][m[0]].data()));
    acc = _mm_xor_si128(acc,
                        *reinterpret_cast<const __m128i *>(SL[9][m[0]].data()));
    acc = _mm_xor_si128(
        acc, *reinterpret_cast<const __m128i *>(SL[10][m[10]].data()));
    acc = _mm_xor_si128(
        acc, *reinterpret_cast<const __m128i *>(SL[11][m[11]].data()));
    acc = _mm_xor_si128(
        acc, *reinterpret_cast<const __m128i *>(SL[12][m[12]].data()));
    acc = _mm_xor_si128(
        acc, *reinterpret_cast<const __m128i *>(SL[13][m[13]].data()));
    acc = _mm_xor_si128(
        acc, *reinterpret_cast<const __m128i *>(SL[14][m[14]].data()));
    acc = _mm_xor_si128(
        acc, *reinterpret_cast<const __m128i *>(SL[15][m[15]].data()));

    _mm_storeu_si128(reinterpret_cast<__m128i *>(msg.data()), acc);
  }

  inline static void XOR(block_t &lhs, const block_t &rhs) {
    for (int i = 0; i < BLOCK_SIZE; ++i) {
      lhs[i] ^= rhs[i];
    }
  }

  inline static void round_func(block_t &lhs, block_t &rhs, int round) {
    block_t tmp_lhs = lhs, tmp_const = iter_consts[round];
    XOR(tmp_lhs, tmp_const);
    func_SL_fast(tmp_lhs);
    XOR(tmp_lhs, rhs);
    rhs = lhs, lhs = tmp_lhs;
  }

  inline void encrypt_func(block_t &msg) {
    for (int i = 0; i < ROUNDS - 1; ++i) {
      block_t tmp_const = round_key[i];
      XOR(msg, tmp_const);
      func_SL_fast(msg);
    }
    block_t tmp_const = round_key[ROUNDS - 1];
    XOR(msg, tmp_const);
  }

  inline static void flush_master_key(key_t &mkey) {
    std::random_device rd;
    std::uniform_int_distribution<uint8_t> dist(0, 255);
    for (int i = 0; i < KEY_SIZE; ++i) {
      mkey[i] = static_cast<uint8_t>(dist(rd));
    }
  }

  inline static void flush_round_keys(const std::array<block_t, 10> &rkeys) {
    std::random_device rd;
    std::uniform_int_distribution<uint8_t> dist(0, 255);
    for (auto key : rkeys) {
      for (int i = 0; i < KEY_SIZE; ++i) {
        key[i] = static_cast<uint8_t>(dist(rd));
      }
    }
  }

  inline static const std::array<block_t, ROUNDS>
  init_round_keys(const key_t &mkey) {
    std::array<block_t, 10> rkeys{};
    block_t left{}, right{};
    int i = 0;
    for (; i < 16; ++i) {
      left[i] = mkey[i];
    }
    for (; i < 32; ++i) {
      right[i % 16] = mkey[i];
    }
    rkeys[0] = left;
    rkeys[1] = right;
    for (i = 1; i < 5; ++i) {
      for (int j = 0; j < 8; ++j) {
        round_func(left, right, (i - 1) * 8 + j);
      }
      rkeys[2 * i] = left;
      rkeys[2 * i + 1] = right;
    }
    return static_cast<const std::array<block_t, 10>>(rkeys);
  }

  inline static void shift_left_bit(block_t &msg) {
    uint8_t carry = 0;
    for (int i = BLOCK_SIZE - 1; i >= 0; --i) {
      uint8_t tmp_carry = msg[i] & 0x80 ? 1 : 0;
      msg[i] <<= 1;
      msg[i] += carry;
      carry = tmp_carry;
    }
  }

  inline const std::array<block_t, 2> init_OMAC_keys() {
    std::array<block_t, 2> mac_keys{};
    block_t zero_vec{}, b_vec{};
    b_vec[BLOCK_SIZE - 1] = B128;
    encrypt_func(zero_vec);
    int MSB1 = zero_vec[0] & 0x80 ? 1 : 0, MSB2 = zero_vec[0] & 0x40 ? 1 : 0;
    shift_left_bit(zero_vec);
    if (MSB1) {
      XOR(zero_vec, b_vec);
    }
    mac_keys[0] = zero_vec;
    if (MSB2) {
      XOR(zero_vec, b_vec);
    }
    mac_keys[1] = zero_vec;
    return mac_keys;
  }

  inline void flush_data(std::vector<uint8_t> filebuf) {
    std::random_device rd;
    std::uniform_int_distribution<uint8_t> dist(0, 255);
    for (int i = 0; i < filebuf.size(); ++i) {
      filebuf[i] = static_cast<uint8_t>(dist(rd));
    }
  }

  inline static void flush_OMAC_keys(const std::array<block_t, 2> &mac_keys) {
    std::random_device rd;
    std::uniform_int_distribution<uint8_t> dist(0, 255);
    for (auto key : mac_keys) {
      for (int i = 0; i < BLOCK_SIZE; ++i) {
        key[i] = static_cast<uint8_t>(dist(rd));
      }
    }
  }
};

#endif // _KUZNECHIK_HPP
