//
// Created by HedgDifuse on 15.11.2024.
//
unsigned long strhash(char *str)
{
    unsigned long hash = 5381;
    int c;

    while ((c = *str++))
        hash = ((hash << 5) + hash) + c; /* hash * 33 + c */

    return hash;
}