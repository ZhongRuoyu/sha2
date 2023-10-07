#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "sha2.h"
#include "sha2_impl.h"

enum { kSHA256Rounds = 64 };

static const uint32_t kSHA256RoundConstants[kSHA256Rounds] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

enum { kSHA512Rounds = 80 };

static const uint64_t kSHA512RoundConstants[kSHA512Rounds] = {
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f,
    0xe9b5dba58189dbbc, 0x3956c25bf348b538, 0x59f111f1b605d019,
    0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242,
    0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235,
    0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3,
    0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65, 0x2de92c6f592b0275,
    0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f,
    0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725,
    0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc,
    0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6,
    0x92722c851482353b, 0xa2bfe8a14cf10364, 0xa81a664bbc423001,
    0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218,
    0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99,
    0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb,
    0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc,
    0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915,
    0xc67178f2e372532b, 0xca273eceea26619c, 0xd186b8c721c0c207,
    0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba,
    0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc,
    0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a,
    0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
};

static uint32_t SHA256LittleSigma0(uint32_t x) {
  return (x >> 7 | x << 25) ^ (x >> 18 | x << 14) ^ (x >> 3);
}

static uint32_t SHA256LittleSigma1(uint32_t x) {
  return (x >> 17 | x << 15) ^ (x >> 19 | x << 13) ^ (x >> 10);
}

static uint32_t SHA256BigSigma0(uint32_t x) {
  return (x >> 2 | x << 30) ^ (x >> 13 | x << 19) ^ (x >> 22 | x << 10);
}

static uint32_t SHA256BigSigma1(uint32_t x) {
  return (x >> 6 | x << 26) ^ (x >> 11 | x << 21) ^ (x >> 25 | x << 7);
}

static uint64_t SHA512LittleSigma0(uint64_t x) {
  return (x >> 1 | x << 63) ^ (x >> 8 | x << 56) ^ (x >> 7);
}

static uint64_t SHA512LittleSigma1(uint64_t x) {
  return (x >> 19 | x << 45) ^ (x >> 61 | x << 3) ^ (x >> 6);
}

static uint64_t SHA512BigSigma0(uint64_t x) {
  return (x >> 28 | x << 36) ^ (x >> 34 | x << 30) ^ (x >> 39 | x << 25);
}

static uint64_t SHA512BigSigma1(uint64_t x) {
  return (x >> 14 | x << 50) ^ (x >> 18 | x << 46) ^ (x >> 41 | x << 23);
}

static uint32_t SHA256Choice(uint32_t x, uint32_t y, uint32_t z) {
  return (x & y) ^ (~x & z);
}

static uint32_t SHA256Majority(uint32_t x, uint32_t y, uint32_t z) {
  return (x & y) ^ (x & z) ^ (y & z);
}

static uint64_t SHA512Choice(uint64_t x, uint64_t y, uint64_t z) {
  return (x & y) ^ (~x & z);
}

static uint64_t SHA512Majority(uint64_t x, uint64_t y, uint64_t z) {
  return (x & y) ^ (x & z) ^ (y & z);
}

void SHA256MessageSchedule(uint32_t words[], const uint8_t block[]) {
  for (size_t i = 0; i < kSHA256Rounds; ++i) {
    if (i < kSHA256BlockSize / 32) {
      words[i] =
          ((uint32_t)block[4 * i] << 24) + ((uint32_t)block[4 * i + 1] << 16) +
          ((uint32_t)block[4 * i + 2] << 8) + ((uint32_t)block[4 * i + 3]);
    } else {
      uint32_t s0 = SHA256LittleSigma0(words[i - 15]);
      uint32_t s1 = SHA256LittleSigma1(words[i - 2]);
      words[i] = words[i - 16] + s0 + words[i - 7] + s1;
    }
  }
}

void SHA512MessageSchedule(uint64_t words[], const uint8_t block[]) {
  for (size_t i = 0; i < kSHA512Rounds; ++i) {
    if (i < kSHA512BlockSize / 64) {
      words[i] =
          ((uint64_t)block[8 * i] << 56) + ((uint64_t)block[8 * i + 1] << 48) +
          ((uint64_t)block[8 * i + 2] << 40) +
          ((uint64_t)block[8 * i + 3] << 32) +
          ((uint64_t)block[8 * i + 4] << 24) +
          ((uint64_t)block[8 * i + 5] << 16) +
          ((uint64_t)block[8 * i + 6] << 8) + ((uint64_t)block[8 * i + 7]);
    } else {
      uint64_t s0 = SHA512LittleSigma0(words[i - 15]);
      uint64_t s1 = SHA512LittleSigma1(words[i - 2]);
      words[i] = words[i - 16] + s0 + words[i - 7] + s1;
    }
  }
}

void SHA256Round(uint32_t state[], uint32_t round_constant,
                 uint32_t schedule_word) {
  uint32_t ch = SHA256Choice(state[4], state[5], state[6]);
  uint32_t temp1 = state[7] + SHA256BigSigma1(state[4]) + ch + round_constant +
                   schedule_word;
  uint32_t maj = SHA256Majority(state[0], state[1], state[2]);
  uint32_t temp2 = SHA256BigSigma0(state[0]) + maj;
  state[7] = state[6];
  state[6] = state[5];
  state[5] = state[4];
  state[4] = state[3] + temp1;
  state[3] = state[2];
  state[2] = state[1];
  state[1] = state[0];
  state[0] = temp1 + temp2;
}

void SHA512Round(uint64_t state[], uint64_t round_constant,
                 uint64_t schedule_word) {
  uint64_t ch = SHA512Choice(state[4], state[5], state[6]);
  uint64_t temp1 = state[7] + SHA512BigSigma1(state[4]) + ch + round_constant +
                   schedule_word;
  uint64_t maj = SHA512Majority(state[0], state[1], state[2]);
  uint64_t temp2 = SHA512BigSigma0(state[0]) + maj;
  state[7] = state[6];
  state[6] = state[5];
  state[5] = state[4];
  state[4] = state[3] + temp1;
  state[3] = state[2];
  state[2] = state[1];
  state[1] = state[0];
  state[0] = temp1 + temp2;
}

void SHA256Compress(uint32_t state[], const uint8_t block[]) {
  uint32_t input_state[kSHA256StateSize / 32];
  memcpy(input_state, state, sizeof(input_state));
  uint32_t words[kSHA256Rounds];
  SHA256MessageSchedule(words, block);
  for (size_t i = 0; i < kSHA256Rounds; ++i) {
    SHA256Round(state, kSHA256RoundConstants[i], words[i]);
  }
  for (size_t i = 0; i < kSHA256StateSize / 32; ++i) {
    state[i] += input_state[i];
  }
}

void SHA512Compress(uint64_t state[], const uint8_t block[]) {
  uint64_t input_state[kSHA512StateSize / 64];
  memcpy(input_state, state, sizeof(input_state));
  uint64_t words[kSHA512Rounds];
  SHA512MessageSchedule(words, block);
  for (size_t i = 0; i < kSHA512Rounds; ++i) {
    SHA512Round(state, kSHA512RoundConstants[i], words[i]);
  }
  for (size_t i = 0; i < kSHA512StateSize / 64; ++i) {
    state[i] += input_state[i];
  }
}
