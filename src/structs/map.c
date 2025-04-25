//
// Created by HedgDifuse on 17.04.2025.
//

#include "map.h"

#include <string.h>

void *map_get(const struct map *map, const size_t key_hash) {
    struct map_entry entry = map->entries[key_hash % map->size];

    while (entry.key_hash != key_hash) {
        entry = *entry.next;
    }

    return entry.value;
}

void *map_put(struct map *map, const size_t key_hash, const void* value) {
    map->size++;
    map->entries = realloc(map->entries, sizeof(struct map_entry) * map->size);

    for (size_t i = 0; i < map->size; i++) {
        const struct map_entry entry = map->entries[i];
        map->entries[entry.key_hash % map->size] = entry;
    }


    return value;
}

void map_init(struct map *map, const size_t size) {

}

void map_clear(struct map *map) {

}