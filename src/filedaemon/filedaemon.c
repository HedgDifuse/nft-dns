//
// Created by HedgDifuse on 10.10.2024.
//
#include "filedaemon.h"

#include "../str/str.h"
#include "../structs/map.h"
#include "../hashset/hashset.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

static const char* DOMAINS_FILE_PATH = "/tmp/nft-dns.d/domains.lst";
static const char* ALIASES_FILE_PATH = "/tmp/nft-dns.d/aliases.lst";

static char *url_only(const char *input, const size_t length) {
    unsigned long result_length = 0;

    for (size_t i = 0; i < length; i++) {
        if ((int) input[i] >= 0x20 && (int) input[i] <= 0x7E) result_length++;
    }

    char *result = calloc(result_length, sizeof(char));
    unsigned long j = 0;

    for (size_t i = 0; i < length; i++) {
        if ((int) input[i] >= 0x20 && (int) input[i] <= 0x7E) {
            result[j] = input[i];
            j++;
        }
    }

    return result;
}

bool update_domains(const volatile hashset_t *domains, time_t *domains_mtim) {
    struct stat result;

    if (stat(DOMAINS_FILE_PATH, &result)) {
        return false;
    }

    if (((long) time(NULL) - result.st_mtim.tv_sec) < 5) {
        *domains_mtim = result.st_mtim.tv_sec;
        return false;
    }

    *domains_mtim = result.st_mtim.tv_sec;

    FILE *file = fopen(DOMAINS_FILE_PATH, "r");

    if (file == NULL) {
        return false;
    }

    hashset_clean(*domains);

    char *line = NULL;
    size_t line_l = 0;

    while(getline(&line, &line_l, file) != -1) {
        if (line[0] == '*') line[0] = '.';

        char* link = url_only(line, strlen(line) - 1);
        const char* normalized_domain = link;
        if (line[1] == '.') normalized_domain++;

        hashset_add(*domains, strhash(normalized_domain));
        free(link);
    }

    if (fclose(file)) {
        perror("fclose error");
    } else if (remove(DOMAINS_FILE_PATH)) {
        perror("remove error");
    }

    return true;
}

bool update_aliases(const volatile struct map *aliases, time_t *aliases_mtim) {
    struct stat result;

    if (stat(ALIASES_FILE_PATH, &result) == 0 && result.st_mtim.tv_sec > *aliases_mtim) {
        *aliases_mtim = result.st_mtim.tv_sec;
    } else {
        return false;
    }

    FILE *file = fopen(ALIASES_FILE_PATH, "r");

    if (file == NULL) {
        return false;
    }

    size_t line_count = 0, line_l = 0;
    char *line;

    while(getline(&line, &line_l, file) != -1) {
        line_count++;
    }

    line_l = 0;
    fseek(file, 0, SEEK_SET);

    map_clear(aliases);
    map_init(aliases, line_count);

    while (getline(&line, &line_count, file) != -1) {
        const char* cname = strtok(line, ":");
        const char* domain = strtok(NULL, ":");

        const char* domain_normalized = calloc(strlen(domain) - 1, sizeof(char));
        strncpy(domain_normalized, domain, strlen(domain) - 1);

        map_put(aliases, strhash(cname), domain_normalized);
    }

    return true;
}

_Noreturn void domains_daemon(const volatile struct daemon_params *params) {
    printf("Start domains reading...\n");

    nice(19);

    time_t domains_mtim = 0,
            aliases_mtim = 0;

    while (true) {
        const bool domains_updated = update_domains(params->domains, &domains_mtim);
        const bool aliases_updated = update_aliases(params->aliases, &aliases_mtim);

        if (domains_updated) {
            printf("Domains updated, new count: %lu\n", hashset_num_items(*params->domains));
        }
        if (aliases_updated) {
            printf("Aliases updated, new count: %lu\n", params->aliases->size);
        }

        sleep(1);
    }
}

pthread_t make_domains_daemon(
    const volatile struct daemon_params *daemon_params
) {
    pthread_t result;
    pthread_create(&result, NULL, domains_daemon, daemon_params);

    return result;
}