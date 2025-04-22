#ifndef Custom_SHA1_H
#define Custom_SHA1_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint32_t state[5];
    uint32_t count[2];
    unsigned char buffer[64];
} Custom_SHA1_CTX;

void Custom_SHA1_Init(Custom_SHA1_CTX* context);
void Custom_SHA1_Update(Custom_SHA1_CTX* context, const unsigned char* data, size_t len);
void Custom_SHA1_Final(unsigned char digest[20], Custom_SHA1_CTX* context);

#ifdef __cplusplus
}
#endif

#endif /* Custom_SHA1_H */
