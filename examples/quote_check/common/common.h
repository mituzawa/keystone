#ifndef COMMON_H
#define COMMON_H

#include <stdint.h>

typedef struct {
    uint16_t quote_size;
    uint16_t sig_size;
    uint16_t ak_pub_size;
    uint8_t quote[2048];
    uint8_t signature[512];
    uint8_t ak_pub[512];
} QuoteResult;

#endif
