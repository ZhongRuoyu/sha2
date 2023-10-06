#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "sha2_impl.h"

size_t SHA256Padding(uint8_t output[], size_t message_length) {
  size_t remainder_bytes = (message_length + 8) % (kSHA256BlockSize / 8);
  size_t filler_bytes = (kSHA256BlockSize / 8) - remainder_bytes;
  size_t zero_bytes = filler_bytes - 1;

  output[0] = 0x80;
  memset(output + 1, 0x00, zero_bytes);
  size_t message_bitsize = message_length * 8;
  output[filler_bytes] = (message_bitsize >> 56) & 0xff;
  output[filler_bytes + 1] = (message_bitsize >> 48) & 0xff;
  output[filler_bytes + 2] = (message_bitsize >> 40) & 0xff;
  output[filler_bytes + 3] = (message_bitsize >> 32) & 0xff;
  output[filler_bytes + 4] = (message_bitsize >> 24) & 0xff;
  output[filler_bytes + 5] = (message_bitsize >> 16) & 0xff;
  output[filler_bytes + 6] = (message_bitsize >> 8) & 0xff;
  output[filler_bytes + 7] = message_bitsize & 0xff;

  return 1 + zero_bytes + 8;
}

size_t SHA512Padding(uint8_t output[], size_t message_length) {
  size_t remainder_bytes = (message_length + 16) % (kSHA512BlockSize / 8);
  size_t filler_bytes = (kSHA512BlockSize / 8) - remainder_bytes;
  size_t zero_bytes = filler_bytes - 1;

  output[0] = 0x80;
  memset(output + 1, 0x00, zero_bytes);
  size_t message_bitsize = message_length * 8;
  output[filler_bytes] = 0x00;
  output[filler_bytes + 1] = 0x00;
  output[filler_bytes + 2] = 0x00;
  output[filler_bytes + 3] = 0x00;
  output[filler_bytes + 4] = 0x00;
  output[filler_bytes + 5] = 0x00;
  output[filler_bytes + 6] = 0x00;
  output[filler_bytes + 7] = 0x00;
  output[filler_bytes + 8] = (message_bitsize >> 56) & 0xff;
  output[filler_bytes + 9] = (message_bitsize >> 48) & 0xff;
  output[filler_bytes + 10] = (message_bitsize >> 40) & 0xff;
  output[filler_bytes + 11] = (message_bitsize >> 32) & 0xff;
  output[filler_bytes + 12] = (message_bitsize >> 24) & 0xff;
  output[filler_bytes + 13] = (message_bitsize >> 16) & 0xff;
  output[filler_bytes + 14] = (message_bitsize >> 8) & 0xff;
  output[filler_bytes + 15] = message_bitsize & 0xff;

  return 1 + zero_bytes + 16;
}
