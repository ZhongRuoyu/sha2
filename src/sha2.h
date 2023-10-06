#ifndef SHA2_H_
#define SHA2_H_

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum { kSHA256DigestLength = 32 };
enum { kSHA256StateSize = 256 };
enum { kSHA256BlockSize = 512 };
struct SHA256Context {
  uint32_t state[kSHA256StateSize / 32];
  uint8_t block[kSHA256BlockSize / 8];
  size_t length;
};
void SHA256Init(struct SHA256Context *ctx);
void SHA256Update(struct SHA256Context *ctx, const void *data, size_t len);
void SHA256Final(uint8_t digest[], const struct SHA256Context *ctx);

enum { kSHA224DigestLength = 28 };
struct SHA224Context {
  uint32_t state[kSHA256StateSize / 32];
  uint8_t block[kSHA256BlockSize / 8];
  size_t length;
};
void SHA224Init(struct SHA224Context *ctx);
void SHA224Update(struct SHA224Context *ctx, const void *data, size_t len);
void SHA224Final(uint8_t digest[], const struct SHA224Context *ctx);

enum { kSHA512DigestLength = 64 };
enum { kSHA512StateSize = 512 };
enum { kSHA512BlockSize = 1024 };
struct SHA512Context {
  uint64_t state[kSHA512StateSize / 64];
  uint8_t block[kSHA512BlockSize / 8];
  size_t length;
};
void SHA512Init(struct SHA512Context *ctx);
void SHA512Update(struct SHA512Context *ctx, const void *data, size_t len);
void SHA512Final(uint8_t digest[], const struct SHA512Context *ctx);

enum { kSHA384DigestLength = 48 };
struct SHA384Context {
  uint64_t state[kSHA512StateSize / 64];
  uint8_t block[kSHA512BlockSize / 8];
  size_t length;
};
void SHA384Init(struct SHA384Context *ctx);
void SHA384Update(struct SHA384Context *ctx, const void *data, size_t len);
void SHA384Final(uint8_t digest[], const struct SHA384Context *ctx);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // SHA2_H_
