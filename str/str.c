#include <ctype.h>
//
// Created by HedgDifuse on 15.11.2024.
//
unsigned long strhash(const char *str) {
    unsigned long hash = 5381;
    int c;

    while ((c = *str++))
        hash = (hash << 5) + hash + tolower(c); /* hash * 33 + c */

    return hash;
}