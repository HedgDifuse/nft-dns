//
// Created by HedgDifuse on 10.10.2024.
//
#include <stdio.h>
#include <stdlib.h>
#include "filedaemon.h"
#include <sys/stat.h>
#include <string.h>
#include <unistd.h>

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

void domains_daemon(const volatile hashset_t *domains) {
    printf("Start domains reading...\n");

    struct timespec prev_file_edit = { 0, 0 };

    for(;;) {
        struct stat file_stat;

        if (stat(DOMAINS_FILE_PATH, &file_stat) != 0) {
            perror("stat");
            sleep(10);
            continue;
        }

        if (file_stat.st_mtim.tv_sec <= prev_file_edit.tv_sec) {
            sleep(1);
            continue;
        }

        prev_file_edit = file_stat.st_mtim;

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

            char* normalized_domain = url_only(line, strlen(line) - 1);
            if (line[1] == '.') normalized_domain++;

            hashset_add(
                *domains,
                normalized_domain,
                strlen(normalized_domain));
        }

        printf("Domains updated, new count: %lu\n", hashset_num_items(*domains));

        sleep(1);
    }
}

pthread_t make_domains_daemon(const volatile hashset_t *domains) {
    pthread_t result;
    pthread_create(&result, NULL, domains_daemon, (void *) domains);

    return result;
}