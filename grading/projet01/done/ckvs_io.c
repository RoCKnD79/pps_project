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

int read_value_file_content(const char* filename, char** buffer_ptr, size_t* buffer_size){
    // open file "filename" in read mode
    M_REQUIRE_NON_NULL(filename);
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
    if(taille_lue != offset){ return ERR_IO; }

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

    // iterate on all entries to find entry matching key
    bool key_not_found = true;
    for(int i=0; i < CKVS_FIXEDSIZE_TABLE; ++i){
        if(strncmp(key, ckvs->entries[i].key, CKVS_MAXKEYLEN) == 0){
            *e_out = &ckvs->entries[i];
            key_not_found = false;
        }
    }

    if(key_not_found){ return ERR_KEY_NOT_FOUND; }

    // check if auth_key and entry's auth_key correspond
    if(ckvs_cmp_sha(&(**e_out).auth_key, auth_key) != 0){ return ERR_DUPLICATE_ID; }

    return ERR_NONE;
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
       || !(((ckvs->header.table_size & (ckvs->header.table_size-1)) == 0) && (ckvs->header.table_size != 0))
       || (ckvs->header.table_size != CKVS_FIXEDSIZE_TABLE)){
        return ERR_CORRUPT_STORE;
    }

    // -------- READING ENTRIES --------
    size_t taille_lue_entree = fread(&ckvs->entries, sizeof(ckvs_entry_t), CKVS_FIXEDSIZE_TABLE, entree);
    if(taille_lue_entree != CKVS_FIXEDSIZE_TABLE){ return ERR_IO; }

    return ERR_NONE;
}

void ckvs_close(struct CKVS *ckvs) {
    if(ckvs == NULL || ckvs->file == NULL){ return; }
    // ftell returns a negative number if the file is already closed
    if(ftell(ckvs->file) != NEG_FTELL) {
        fclose(ckvs->file);
        ckvs->file = NULL;
    }
}