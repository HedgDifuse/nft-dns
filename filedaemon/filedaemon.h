//
// Created by HedgDifuse on 10.10.2024.
//
#pragma once
#include <pthread.h>
#include "../hashset/hashset.h"

pthread_t make_domains_daemon(const volatile hashset_t *domains);