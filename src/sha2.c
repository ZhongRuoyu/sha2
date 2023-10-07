#include "sha2.h"

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "sha2_impl.h"

static const uint32_t kSHA256IV[kSHA256StateSize / 32] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
};

static const uint32_t kSHA224IV[kSHA256StateSize / 32] = {
    0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
    0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4,
};

static const uint64_t kSHA512IV[kSHA512StateSize / 64] = {
    0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1, 0x510e527fade682d1, 0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
};

static const uint64_t kSHA384IV[kSHA512StateSize / 64] = {
    0xcbbb9d5dc1059ed8, 0x629a292a367cd507, 0x9159015a3070dd17,
    0x152fecd8f70e5939, 0x67332667ffc00b31, 0x8eb44a8768581511,
    0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4,
};

void SHA256Init(struct SHA256Context *ctx) {
  memcpy(ctx->state, kSHA256IV, sizeof(kSHA256IV));
  ctx->length = 0;
}

void SHA224Init(struct SHA224Context *ctx) {
  memcpy(ctx->state, kSHA224IV, sizeof(kSHA224IV));
  ctx->length = 0;
}

void SHA512Init(struct SHA512Context *ctx) {
  memcpy(ctx->state, kSHA512IV, sizeof(kSHA512IV));
  ctx->length = 0;
}

void SHA384Init(struct SHA384Context *ctx) {
  memcpy(ctx->state, kSHA384IV, sizeof(kSHA384IV));
  ctx->length = 0;
}

void SHA256Update(struct SHA256Context *ctx, const void *data, size_t len) {
  for (size_t i = 0; i < len; ++i) {
    ctx->block[ctx->length % (kSHA256BlockSize / 8)] =
        ((const uint8_t *)data)[i];
    ++ctx->length;
    if (ctx->length % (kSHA256BlockSize / 8) == 0) {
      SHA256Compress(ctx->state, ctx->block);
    }
  }
}

void SHA224Update(struct SHA224Context *ctx, const void *data, size_t len) {
  for (size_t i = 0; i < len; ++i) {
    ctx->block[ctx->length % (kSHA256BlockSize / 8)] =
        ((const uint8_t *)data)[i];
    ++ctx->length;
    if (ctx->length % (kSHA256BlockSize / 8) == 0) {
      SHA256Compress(ctx->state, ctx->block);
    }
  }
}

void SHA512Update(struct SHA512Context *ctx, const void *data, size_t len) {
  for (size_t i = 0; i < len; ++i) {
    ctx->block[ctx->length % (kSHA512BlockSize / 8)] =
        ((const uint8_t *)data)[i];
    ++ctx->length;
    if (ctx->length % (kSHA512BlockSize / 8) == 0) {
      SHA512Compress(ctx->state, ctx->block);
    }
  }
}

void SHA384Update(struct SHA384Context *ctx, const void *data, size_t len) {
  for (size_t i = 0; i < len; ++i) {
    ctx->block[ctx->length % (kSHA512BlockSize / 8)] =
        ((const uint8_t *)data)[i];
    ++ctx->length;
    if (ctx->length % (kSHA512BlockSize / 8) == 0) {
      SHA512Compress(ctx->state, ctx->block);
    }
  }
}

void SHA256Final(uint8_t digest[], const struct SHA256Context *ctx) {
  uint8_t padded_buffer[2 * (kSHA256BlockSize / 8)];
  size_t original_length = ctx->length % (kSHA256BlockSize / 8);
  memcpy(padded_buffer, ctx->block, original_length);

  size_t padding_length =
      SHA256Padding(padded_buffer + original_length, ctx->length);
  size_t padded_length = original_length + padding_length;
  assert(padded_length == kSHA256BlockSize / 8 ||
         padded_length == 2ULL * (kSHA256BlockSize / 8));

  uint32_t state[kSHA256StateSize / 32];
  memcpy(state, ctx->state, sizeof(state));
  for (size_t offset = 0; offset < padded_length;
       offset += (kSHA256BlockSize / 8)) {
    SHA256Compress(state, padded_buffer + offset);
  }

  for (size_t i = 0; i < kSHA256DigestLength / 4; ++i) {
    digest[4 * i] = (state[i] >> 24) & 0xff;
    digest[4 * i + 1] = (state[i] >> 16) & 0xff;
    digest[4 * i + 2] = (state[i] >> 8) & 0xff;
    digest[4 * i + 3] = state[i] & 0xff;
  }
}

void SHA224Final(uint8_t digest[], const struct SHA224Context *ctx) {
  uint8_t padded_buffer[2 * (kSHA256BlockSize / 8)];
  size_t original_length = ctx->length % (kSHA256BlockSize / 8);
  memcpy(padded_buffer, ctx->block, original_length);

  size_t padding_length =
      SHA256Padding(padded_buffer + original_length, ctx->length);
  size_t padded_length = original_length + padding_length;
  assert(padded_length == kSHA256BlockSize / 8 ||
         padded_length == 2ULL * (kSHA256BlockSize / 8));

  uint32_t state[kSHA256StateSize / 32];
  memcpy(state, ctx->state, sizeof(state));
  for (size_t offset = 0; offset < padded_length;
       offset += (kSHA256BlockSize / 8)) {
    SHA256Compress(state, padded_buffer + offset);
  }

  for (size_t i = 0; i < kSHA224DigestLength / 4; ++i) {
    digest[4 * i] = (state[i] >> 24) & 0xff;
    digest[4 * i + 1] = (state[i] >> 16) & 0xff;
    digest[4 * i + 2] = (state[i] >> 8) & 0xff;
    digest[4 * i + 3] = state[i] & 0xff;
  }
}

void SHA512Final(uint8_t digest[], const struct SHA512Context *ctx) {
  uint8_t padded_buffer[2 * (kSHA512BlockSize / 8)];
  size_t original_length = ctx->length % (kSHA512BlockSize / 8);
  memcpy(padded_buffer, ctx->block, original_length);

  size_t padding_length =
      SHA512Padding(padded_buffer + original_length, ctx->length);
  size_t padded_length = original_length + padding_length;
  assert(padded_length == (kSHA512BlockSize / 8) ||
         padded_length == 2ULL * (kSHA512BlockSize / 8));

  uint64_t state[kSHA512StateSize / 64];
  memcpy(state, ctx->state, sizeof(state));
  for (size_t offset = 0; offset < padded_length;
       offset += (kSHA512BlockSize / 8)) {
    SHA512Compress(state, padded_buffer + offset);
  }

  for (size_t i = 0; i < kSHA512DigestLength / 8; ++i) {
    digest[8 * i] = (state[i] >> 56) & 0xff;
    digest[8 * i + 1] = (state[i] >> 48) & 0xff;
    digest[8 * i + 2] = (state[i] >> 40) & 0xff;
    digest[8 * i + 3] = (state[i] >> 32) & 0xff;
    digest[8 * i + 4] = (state[i] >> 24) & 0xff;
    digest[8 * i + 5] = (state[i] >> 16) & 0xff;
    digest[8 * i + 6] = (state[i] >> 8) & 0xff;
    digest[8 * i + 7] = state[i] & 0xff;
  }
}

void SHA384Final(uint8_t digest[], const struct SHA384Context *ctx) {
  uint8_t padded_buffer[2 * (kSHA512BlockSize / 8)];
  size_t original_length = ctx->length % (kSHA512BlockSize / 8);
  memcpy(padded_buffer, ctx->block, original_length);

  size_t padding_length =
      SHA512Padding(padded_buffer + original_length, ctx->length);
  size_t padded_length = original_length + padding_length;
  assert(padded_length == (kSHA512BlockSize / 8) ||
         padded_length == 2ULL * (kSHA512BlockSize / 8));

  uint64_t state[kSHA512StateSize / 64];
  memcpy(state, ctx->state, sizeof(state));
  for (size_t offset = 0; offset < padded_length;
       offset += (kSHA512BlockSize / 8)) {
    SHA512Compress(state, padded_buffer + offset);
  }

  for (size_t i = 0; i < kSHA384DigestLength / 8; ++i) {
    digest[8 * i] = (state[i] >> 56) & 0xff;
    digest[8 * i + 1] = (state[i] >> 48) & 0xff;
    digest[8 * i + 2] = (state[i] >> 40) & 0xff;
    digest[8 * i + 3] = (state[i] >> 32) & 0xff;
    digest[8 * i + 4] = (state[i] >> 24) & 0xff;
    digest[8 * i + 5] = (state[i] >> 16) & 0xff;
    digest[8 * i + 6] = (state[i] >> 8) & 0xff;
    digest[8 * i + 7] = state[i] & 0xff;
  }
}
