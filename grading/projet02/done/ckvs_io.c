#include <stdlib.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <string.h>
#include <assert.h>
#include <stdbool.h>

#include "ckvs.h"
#include "ckvs_io.h"
#include "ckvs_utils.h"
#include "ckvs_crypto.h"

#define NEG_FTELL -1

static int ckvs_write_entry_to_disk(struct CKVS *ckvs, uint32_t idx);
static uint32_t ckvs_hashkey(struct CKVS *ckvs, const char *key);

int read_value_file_content(const char* filename, char** buffer_ptr, size_t* buffer_size){
    // open file "filename" in read mode
    M_REQUIRE_NON_NULL(filename);
    M_REQUIRE_NON_NULL(buffer_ptr);
    M_REQUIRE_NON_NULL(buffer_size);

    FILE* entree = fopen(filename,"rb");
    if(entree == NULL){ return ERR_INVALID_ARGUMENT; }

    // place cursor at the end of the file (fseek) to then get the size of the file (ftell)
    int seek_end = fseek(entree, 0, SEEK_END);
    if(seek_end != ERR_NONE){ return ERR_IO; }

    //to get size of the file
    size_t offset = ftell(entree);
    if(offset == NEG_FTELL){ return ERR_IO; }
    size_t b_size = offset + 1; // +1 to add the '\0' at the end

    // place cursor at the beginning of the file
    int seek_start = fseek(entree, 0, SEEK_SET);
    if(seek_start != ERR_NONE){ return ERR_IO; }

    // store the contents of the file into buffer and add '\0' at the end
    char* buffer = calloc(b_size, sizeof(char));
    size_t taille_lue = fread(buffer, sizeof(char), offset, entree);
    if(taille_lue != offset){ 
        free(buffer);
        return ERR_IO; 
        }

    *buffer_ptr = buffer;
    *buffer_size = b_size;

    return ERR_NONE;
}

int ckvs_write_encrypted_value(struct CKVS *ckvs, struct ckvs_entry *e, const unsigned char *buf, uint64_t buflen) {

    M_REQUIRE_NON_NULL(buf);
    M_REQUIRE_NON_NULL(ckvs);
    M_REQUIRE_NON_NULL(e);

    // move cursor to the end of the file (where "buf" will be written)
    int err_seek = fseek(ckvs->file, 0, SEEK_END);
    if(err_seek != ERR_NONE){ return ERR_IO; }

    // get and then store the value's position in the file in the correspondin entry "e"
    int place_before_set = ftell(ckvs->file);
    if(place_before_set == NEG_FTELL){ return ERR_IO; }

    e->value_off = place_before_set;

    // write "buf" and store its length in the corresponding entry "e"
    int err_write = fwrite(buf, sizeof(char), buflen, ckvs->file);
    if(err_write != buflen){ return ERR_IO; }

    e->value_len = buflen;

    // idx gives us the index of the entry in ckvs->entries
    uint32_t idx = e - ckvs->entries;

    // update the new entry of ckvs->entries in the database
    int ret_err = ckvs_write_entry_to_disk(ckvs, idx);

    return ret_err;
}

static int ckvs_write_entry_to_disk(struct CKVS *ckvs, uint32_t idx) {
    // place cursor to where info on ckvs->entris[idx] is located in the database
    M_REQUIRE_NON_NULL(ckvs);
    M_REQUIRE_NON_NULL(ckvs->file);

    size_t place = sizeof(ckvs_header_t) + idx*sizeof(ckvs_entry_t);
    int seek = fseek(ckvs->file, place, SEEK_SET);
    if(seek != ERR_NONE){ return ERR_IO; }

    // update info on the entry in the database with the new entry (which has new c2, value_off and value_len values)
    size_t err = fwrite(&ckvs->entries[idx], sizeof(ckvs_entry_t), 1, ckvs->file);
    if(err != 1){ return ERR_IO; }

    return ERR_NONE;
}

int ckvs_find_entry(struct CKVS *ckvs, const char *key, const struct ckvs_sha *auth_key, struct ckvs_entry **e_out){

    M_REQUIRE_NON_NULL(ckvs);
    M_REQUIRE_NON_NULL(key);
    M_REQUIRE_NON_NULL(auth_key);
    M_REQUIRE_NON_NULL(e_out);

    uint32_t idx = ckvs_hashkey(ckvs, key);
    uint32_t idx_record = idx;

    bool hit = false;

    while(!hit) {

        if(strlen(ckvs->entries[idx].key) == 0) {
            return ERR_KEY_NOT_FOUND;
        } // if key corresponds to idx's entry key => 'hit'
        else if(strncmp(key, ckvs->entries[idx].key, CKVS_MAXKEYLEN) == 0) {
            *e_out = &ckvs->entries[idx];
            hit = true;
        } // there was a collision => increase idx (linear probing)
        else { 
            idx = (idx + 1) % (ckvs->header.table_size - 1);
            if(idx_record == idx){ return ERR_KEY_NOT_FOUND; }
        }
    }

    if(ckvs_cmp_sha(&(**e_out).auth_key, auth_key) != 0){ return ERR_DUPLICATE_ID; }

    return ERR_NONE;
}

int ckvs_new_entry(struct CKVS *ckvs, const char *key, struct ckvs_sha *auth_key, struct ckvs_entry **e_out) {

    M_REQUIRE_NON_NULL(ckvs);
    M_REQUIRE_NON_NULL(key);
    M_REQUIRE_NON_NULL(auth_key);
    M_REQUIRE_NON_NULL(e_out);
    
    uint32_t hash = ckvs_hashkey(ckvs, key);

    // if key already exists 
    if (ckvs_find_entry(ckvs, key, auth_key, e_out) != ERR_KEY_NOT_FOUND) {
        //reset *e_out which contains an entry due to the function, but shouldn't since no new entry was created
        *e_out = NULL;
        return ERR_DUPLICATE_ID; 
    }

    // no space to add a new entry
    if(ckvs->header.num_entries + 1 > ckvs->header.threshold_entries) { 
        ckvs_close(ckvs);
        return ERR_MAX_FILES; }
    // key is too long
    if(strlen(key)+1 > CKVS_MAXKEYLEN) { return ERR_INVALID_ARGUMENT; }

    // everything seems good => update the number of entries contained in ckvs
    ckvs->header.num_entries += 1;

    // rewriting the header in the file
    int ret = fseek(ckvs->file, sizeof(ckvs_header_t) - sizeof(uint32_t), SEEK_SET);
    if(ret != 0){ return ERR_IO; }
    int write = fwrite(&ckvs->header.num_entries, sizeof(uint32_t), 1, ckvs->file);
    if(write != 1){ return ERR_IO; }

    // ----------------- initialise new entry ----------------- (key, auth_key)
    ckvs_entry_t new_entry;
    memset(&new_entry, 0, sizeof(ckvs_entry_t));
    strncpy(new_entry.key, key, CKVS_MAXKEYLEN);
    // case where key != CKVS_MAXKEYLEN => it must be "null-terminated"
    if (strlen(key) < CKVS_MAXKEYLEN) { 
        new_entry.key[strlen(key)+1] = '\0';
    }
    new_entry.auth_key = *auth_key;
    // --------------------------------------------------------

    *e_out = &new_entry;

    ckvs->entries[hash] = new_entry;

    ckvs_write_entry_to_disk(ckvs, hash);

    ckvs_close(ckvs);

    return ERR_NONE;
}


static uint32_t ckvs_hashkey(struct CKVS *ckvs, const char *key) {
    // compute the SHA of key
    char hash_key[SHA256_DIGEST_LENGTH];
    SHA256(key, strlen(key), hash_key);

    // extract first 4 bytes of hash_key
    uint32_t four_bytes;
    memcpy(&four_bytes, hash_key, 4);

    // header.tables_size is a power of 2 (checked in ckvs_open)
    // => create a mask to extract the corresponding LSBs from the four_bytes above
    uint32_t mask = ckvs->header.table_size - 1;
    uint32_t hash_val = four_bytes & mask;

    return hash_val;
}


int ckvs_open(const char *filename, struct CKVS *ckvs) {
    M_REQUIRE_NON_NULL(ckvs);
    memset(ckvs, 0, sizeof(CKVS_t));

    // Opening FILE "filename" in read and write mode
    M_REQUIRE_NON_NULL(filename);
    FILE* entree = fopen(filename,"r+b");
    if(entree == NULL){ return ERR_IO; }

    // store the file in ckvs
    ckvs->file = entree;
    // -------- READING HEADER --------
    size_t taille_lue = fread(&ckvs->header, sizeof(ckvs_header_t), 1, entree);
    if(taille_lue != 1){ return ERR_IO; }

    if((strncmp(ckvs->header.header_string, CKVS_HEADERSTRING_PREFIX, strlen(CKVS_HEADERSTRING_PREFIX)) != 0)
       || (ckvs->header.version != 1)
       || !(((ckvs->header.table_size & (ckvs->header.table_size-1)) == 0) && (ckvs->header.table_size != 0))){
        return ERR_CORRUPT_STORE;
    }
    
    // entries allocation
    ckvs->entries = calloc(ckvs->header.table_size, sizeof(ckvs_entry_t));

    // -------- READING ENTRIES --------
    size_t taille_lue_entree = fread(ckvs->entries, sizeof(ckvs_entry_t), ckvs->header.table_size, entree);
    if(taille_lue_entree != ckvs->header.table_size){
        ckvs_close(ckvs);
        return ERR_IO;
    }

    return ERR_NONE;
}

void ckvs_close(struct CKVS *ckvs) {
    if(ckvs == NULL || ckvs->file == NULL || ckvs->entries == NULL){ return; }
    // ftell returns a negative number if the file is already closed
    if(ftell(ckvs->file) != NEG_FTELL) {
        fclose(ckvs->file);
        ckvs->file = NULL;
    }
    free(ckvs->entries);
    ckvs->entries = NULL;
}