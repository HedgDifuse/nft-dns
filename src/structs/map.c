//
// Created by HedgDifuse on 17.04.2025.
//

#include "map.h"

#include <string.h>

void *map_get(const struct map *map, const size_t key_hash) {
    return map->pointer[key_hash % map->size];
}

void *map_put(struct map *map, const size_t key_hash, const void* value) {
    map->pointer[key_hash % map->size] = value;

    return value;
}

void map_init(struct map *map, const size_t size) {
    map->pointer = calloc(size, sizeof(void*));
    map->size = size;
}

void map_clear(struct map *map) {
    for (size_t i = 0; i < map->size; i++) {
        free(map->pointer[i]);
    }
    map->size = 0;
    free(map->pointer);
    map->pointer = NULL;
}