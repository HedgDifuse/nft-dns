#include <string.h>
//
// Created by HedgDifuse on 15.11.2024.
//
size_t strhash(const char *str) {
    size_t hash = 0;

    for (; *str; ++str)
        hash ^= *str + 0x9e3779b9 + (hash << 6) + (hash >> 2);

    return hash;
}