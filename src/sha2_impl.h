#ifndef SHA2_IMPL_H_
#define SHA2_IMPL_H_

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

void SHA256MessageSchedule(uint32_t words[], const uint8_t block[]);
void SHA256Round(uint32_t state[], uint32_t round_constant,
                 uint32_t schedule_word);
void SHA256Compress(uint32_t state[], const uint8_t block[]);
size_t SHA256Padding(uint8_t output[], size_t message_length);

void SHA512MessageSchedule(uint64_t words[], const uint8_t block[]);
void SHA512Round(uint64_t state[], uint64_t round_constant,
                 uint64_t schedule_word);
void SHA512Compress(uint64_t state[], const uint8_t block[]);
size_t SHA512Padding(uint8_t output[], size_t message_length);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // SHA2_IMPL_H_
