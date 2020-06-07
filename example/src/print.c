#include "print.h"

void print_hash(const uint8_t *hash, size_t len) {
    for(int i = 0; i < len; i++) {
        printf("%02x", hash[i]);
    }
    putchar( '\n' );
}
