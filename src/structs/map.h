//
// Created by HedgDifuse on 17.04.2025.
//

#pragma once

#ifndef MAP_H
#define MAP_H

#include "stdlib.h"

struct map {
    void **pointer;
    size_t size;
};

void *map_get(const struct map *map, size_t key_hash);

void *map_put(struct map *map, size_t key_hash, const void* value);

void map_init(struct map *map, size_t size);

void map_clear(struct map *map);

#endif //MAP_H
