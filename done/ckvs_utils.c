#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include "ckvs.h"
#include "util.h"

#define ERR_DECODE -1

void print_header(const struct ckvs_header* header){
    pps_printf("CKVS Header type       : %s\n", header->header_string);
    pps_printf("CKVS Header version    : %u\n", header->version);
    pps_printf("CKVS Header table_size : %u\n", header->table_size);
    pps_printf("CKVS Header threshold  : %u\n", header->threshold_entries);
    pps_printf("CKVS Header num_entries: %u\n", header->num_entries);
}

void print_entry(const struct ckvs_entry* entry){
    pps_printf("    Key   : ");
    pps_printf(STR_LENGTH_FMT(CKVS_MAXKEYLEN), entry->key);
    pps_printf("\n");
    pps_printf("    Value : off %lu len %lu\n", entry->value_off, entry->value_len);
    print_SHA("    Auth  ",&entry->auth_key );
    print_SHA("    C2    ", &entry->c2);
}

void print_SHA(const char *prefix, const struct ckvs_sha* sha){
    char buffer[SHA256_PRINTED_STRLEN];
    SHA256_to_string(sha, buffer);
    pps_printf("%-5s: %s\n", prefix, buffer);
}

void hex_encode(const uint8_t *in, size_t len, char* buf){
    if(in == NULL || buf == NULL){ return; }
    for(size_t i=0; i < len; ++i){
        sprintf(&buf[2*i], "%02x", in[i]);
    }
}

void SHA256_to_string(const struct ckvs_sha* sha, char* buf){
    hex_encode(sha->sha, SHA256_DIGEST_LENGTH, buf);
}

int hex_decode(const char *in, uint8_t *buf){
    if(in == NULL || buf == NULL){ return ERR_DECODE; }

    int ret_toul = 0;
    bool odd = strlen(in)%2 != 0;
    int octet_size = odd ? (strlen(in)/2) + 1 : strlen(in)/2;

    char temp[2] = {'0'};
    if(odd) {
        temp[1] = in[0];
        buf[0] = strtoul(temp, NULL, 16);
        ret_toul += 1;
        for(int i = 1; i < octet_size; i++) {
            temp[0] = in[2*i-1];
            temp[1] = in[2*i];
            buf[i] = strtoul(temp, NULL, 16);
            ret_toul += 1;
        }
    } else {
        for(int i = 0; i < octet_size; i++) {
            temp[0] = in[2*i];
            temp[1] = in[2*i+1];
            buf[i] = strtoul(temp, NULL, 16);
            ret_toul += 1;
        }
    }
    
    return ret_toul;
}

int SHA256_from_string(const char *in, struct ckvs_sha *sha) {
    return hex_decode(in, sha->sha);
}

int ckvs_cmp_sha(const struct ckvs_sha *a, const struct ckvs_sha *b){
    return memcmp(a->sha, b->sha, SHA256_DIGEST_LENGTH);
}