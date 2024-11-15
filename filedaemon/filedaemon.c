//
// Created by HedgDifuse on 10.10.2024.
//
#include "filedaemon.h"
#include "../hash/hash.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

static const char* DOMAINS_FILE_PATH = "/tmp/nft-dns.d/domains.lst";

static char *url_only(const char *input, const size_t length) {
    unsigned long result_length = 0;

    for (size_t i = 0; i < length; i++) {
        if ((int) input[i] >= 0x20 && (int) input[i] <= 0x7E) result_length++;
    }

    char *result = malloc(result_length * sizeof(char));
    unsigned long j = 0;

    for (size_t i = 0; i < length; i++) {
        if ((int) input[i] >= 0x20 && (int) input[i] <= 0x7E) {
            result[j] = input[i];
            j++;
        }
    }

    return result;
}

_Noreturn void domains_daemon(const volatile hashset_t *domains) {
    printf("Start domains reading...\n");

    unsigned long previous_size = 0;
    time_t prev_mtim = 0;

    for(;;) {
        struct stat result;

        if (stat(DOMAINS_FILE_PATH, &result) == 0 && result.st_mtim.tv_sec > prev_mtim) {
            prev_mtim = result.st_mtim.tv_sec;
        } else {
            sleep(1);
            continue;
        }

        FILE *file = fopen(DOMAINS_FILE_PATH, "r");

        if (file == NULL) {
            sleep(1);
            continue;
        }

        hashset_clean(*domains);

        char *line;
        size_t line_l = 0;

        while(getline(&line, &line_l, file) != -1) {
            if (line[0] == '*') line[0] = '.';

            char* link = url_only(line, strlen(line) - 1);
            char* normalized_domain = link;
            if (line[1] == '.') normalized_domain++;

            hashset_add(*domains, strhash(normalized_domain));
            free(link);
        }

        const unsigned long new_size = hashset_num_items(*domains);

        if (new_size != previous_size) {
            printf("Domains updated, new count: %lu\n", new_size);
            previous_size = new_size;
        }

        if (fclose(file))   /* Close the stream. */
            perror("fclose error");
        sleep(1);
    }
}

pthread_t make_domains_daemon(const volatile hashset_t *domains) {
    pthread_t result;
    pthread_create(&result, NULL, (void *(*)(void *)) domains_daemon, domains);

    return result;
}