//
// Created by HedgDifuse on 17.04.2025.
//

#pragma once

#ifndef MAP_H
#define MAP_H

#import "stdlib.h"

struct map {
    struct map_entry* entries;
    size_t size;
};

struct map_entry {
    struct map_entry *next;
    size_t key_hash;
    void* value;
};

void *map_get(const struct map *map, size_t key_hash);

void *map_put(struct map *map, size_t key_hash, const void* value);

void map_init(struct map *map, size_t size);

void map_clear(struct map *map);

#endif //MAP_H
