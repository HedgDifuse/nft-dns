#pragma once

#include "../hashset/hashset.h"
#include "../structs/map.h"
#include <pthread.h>

struct daemon_params {
    const volatile hashset_t *domains;
    const volatile struct map *aliases;
};

pthread_t make_domains_daemon(
    const volatile struct daemon_params *daemon_params
);