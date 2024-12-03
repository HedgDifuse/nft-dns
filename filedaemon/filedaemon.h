#pragma once
#include <pthread.h>
#include "../hashset/hashset.h"

pthread_t make_domains_daemon(const volatile hashset_t *domains);