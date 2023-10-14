#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sha2.h"

enum { kBufsize = (1 << 20) /* 1 MiB */ };

static enum {
  kAll,
  kSHA256,
  kSHA224,
  kSHA512,
  kSHA384,
} mode;

static void PrintDigest(const char *algorithm, uint8_t digest[],
                        size_t digest_length, const char *filename) {
  if (algorithm != NULL) {
    printf("%s: ", algorithm);
  }
  for (size_t i = 0; i < digest_length; ++i) {
    printf("%02x", digest[i]);
  }
  if (filename != NULL) {
    printf("  %s", filename);
  }
  printf("\n");
}

static void ProcessFile(const char *filename) {
  FILE *file;
  const char *effective_filename;
  if (strcmp(filename, "-") == 0) {
    file = stdin;
    effective_filename = "stdin";
  } else {
    file = fopen(filename, "rb");
    effective_filename = filename;
    if (file == NULL) {
      fprintf(stderr, "Error opening %s: %s\n", effective_filename,
              // NOLINTNEXTLINE(concurrency-mt-unsafe)
              strerror(errno));
      return;
    }
  }

  struct SHA256Context *sha256_ctx = NULL;
  struct SHA224Context *sha224_ctx = NULL;
  struct SHA512Context *sha512_ctx = NULL;
  struct SHA384Context *sha384_ctx = NULL;
  if (mode == kAll || mode == kSHA256) {
    sha256_ctx = malloc(sizeof(struct SHA256Context));
    SHA256Init(sha256_ctx);
  }
  if (mode == kAll || mode == kSHA224) {
    sha224_ctx = malloc(sizeof(struct SHA224Context));
    SHA224Init(sha224_ctx);
  }
  if (mode == kAll || mode == kSHA512) {
    sha512_ctx = malloc(sizeof(struct SHA512Context));
    SHA512Init(sha512_ctx);
  }
  if (mode == kAll || mode == kSHA384) {
    sha384_ctx = malloc(sizeof(struct SHA384Context));
    SHA384Init(sha384_ctx);
  }

  uint8_t buffer[kBufsize];
  for (;;) {
    size_t len = fread(buffer, sizeof(uint8_t), kBufsize, file);
    if (len == 0) {
      if (feof(file)) {
        break;
      }
      if (ferror(file)) {
        fprintf(stderr, "Error reading from %s: %s\n", effective_filename,
                // NOLINTNEXTLINE(concurrency-mt-unsafe)
                strerror(errno));
        goto cleanup;
      }
      fprintf(stderr, "Unknown error processing %s", effective_filename);
      goto cleanup;
    }

    if (mode == kAll || mode == kSHA256) {
      SHA256Update(sha256_ctx, buffer, len);
    }
    if (mode == kAll || mode == kSHA224) {
      SHA224Update(sha224_ctx, buffer, len);
    }
    if (mode == kAll || mode == kSHA512) {
      SHA512Update(sha512_ctx, buffer, len);
    }
    if (mode == kAll || mode == kSHA384) {
      SHA384Update(sha384_ctx, buffer, len);
    }
  }

  if (mode == kAll) {
    printf("%s:\n", filename);
  }
  if (mode == kAll || mode == kSHA256) {
    uint8_t sha256_digest[kSHA256DigestLength];
    SHA256Final(sha256_digest, sha256_ctx);
    PrintDigest(mode == kAll ? "SHA256" : NULL, sha256_digest,
                kSHA256DigestLength, mode != kAll ? filename : NULL);
  }
  if (mode == kAll || mode == kSHA224) {
    uint8_t sha224_digest[kSHA224DigestLength];
    SHA224Final(sha224_digest, sha224_ctx);
    PrintDigest(mode == kAll ? "SHA224" : NULL, sha224_digest,
                kSHA224DigestLength, mode != kAll ? filename : NULL);
  }
  if (mode == kAll || mode == kSHA512) {
    uint8_t sha512_digest[kSHA512DigestLength];
    SHA512Final(sha512_digest, sha512_ctx);
    PrintDigest(mode == kAll ? "SHA512" : NULL, sha512_digest,
                kSHA512DigestLength, mode != kAll ? filename : NULL);
  }
  if (mode == kAll || mode == kSHA384) {
    uint8_t sha384_digest[kSHA384DigestLength];
    SHA384Final(sha384_digest, sha384_ctx);
    PrintDigest(mode == kAll ? "SHA384" : NULL, sha384_digest,
                kSHA384DigestLength, mode != kAll ? filename : NULL);
  }
  if (mode == kAll) {
    printf("\n");
  }

cleanup:
  if (file != stdin) {
    fclose(file);
  }
  free(sha256_ctx);
  free(sha224_ctx);
  free(sha512_ctx);
  free(sha384_ctx);
}

int main(int argc, char *argv[]) {
  const char *prog_name = strrchr(argv[0], '/');
  if (prog_name == NULL) {
    prog_name = argv[0];
  } else {
    ++prog_name;
  }

  if (strcmp(prog_name, "sha256") == 0 || strcmp(prog_name, "sha256sum") == 0) {
    mode = kSHA256;
  } else if (strcmp(prog_name, "sha224") == 0 ||
             strcmp(prog_name, "sha224sum") == 0) {
    mode = kSHA224;
  } else if (strcmp(prog_name, "sha512") == 0 ||
             strcmp(prog_name, "sha512sum") == 0) {
    mode = kSHA512;
  } else if (strcmp(prog_name, "sha384") == 0 ||
             strcmp(prog_name, "sha384sum") == 0) {
    mode = kSHA384;
  } else {
    mode = kAll;
  }

  if (argc > 1) {
    for (int i = 1; i < argc; ++i) {
      ProcessFile(argv[i]);
    }
  } else {
    ProcessFile("-");
  }
}
