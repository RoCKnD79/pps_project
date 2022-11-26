#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "ckvs.h"
#include "ckvs_io.h"
#include "ckvs_crypto.h"
#include "ckvs_local.h"

#include "openssl/evp.h"
#include "openssl/rand.h"


int check_args(int argc, int arg_cmd){
    if(argc < arg_cmd){
        return ERR_NOT_ENOUGH_ARGUMENTS;
    }else if(argc > arg_cmd){
        return ERR_TOO_MANY_ARGUMENTS;
    }else{
        return ERR_NONE;
    }
}

void free_buffer(unsigned char* buffer){
    free(buffer);
    buffer = NULL;
}

int ckvs_local_stats(const char *filename, int optargc, char* optargv[]){

    int check = check_args(optargc, ARG_STATS);
    if(check != 0){ return check; }

    // open database file, store its contents into ckvs
    CKVS_t ckvs;
    int err_open = ckvs_open(filename, &ckvs);
    if(err_open != ERR_NONE){ return err_open; }

    // display header of database
    print_header(&ckvs.header);

    // print all database entries
    for(int i=0; i < ckvs.header.table_size; ++i){
        if(strlen(ckvs.entries[i].key) > 0){
            print_entry(&ckvs.entries[i]);
        }
    }

    // close database file
    ckvs_close(&ckvs);

    return ERR_NONE;
}

int ckvs_local_getset(const char *filename, const char *key, const char *pwd, const char* set_value){

    M_REQUIRE_NON_NULL(filename);
    M_REQUIRE_NON_NULL(key);
    M_REQUIRE_NON_NULL(pwd);

    // open database file, store its contents into ckvs
    CKVS_t ckvs;
    int err_open = ckvs_open(filename, &ckvs);
    if(err_open != ERR_NONE){ 
        ckvs_close(&ckvs);
        return err_open;
    }

    // generates the stretched_key, auth_key and c1 and stores them in mr
    ckvs_memrecord_t mr;
    int err_pwd = ckvs_client_encrypt_pwd(&mr, key, pwd);
    if(err_pwd != ERR_NONE) { 
        ckvs_close(&ckvs);
        return err_pwd;
    }

    // find the entry corresponding to "key"
    ckvs_entry_t* k_out;

    int err_entry = ckvs_find_entry(&ckvs, key, &mr.auth_key, &k_out);
    if(err_entry != ERR_NONE){ 
        ckvs_close(&ckvs);
        return err_entry;
    }

    // --------- SET ---------
    // generate a new random c2 key
    if(set_value != NULL) {
        int err_rand = RAND_bytes(k_out->c2.sha, SHA256_DIGEST_LENGTH);
        if(err_rand != RAND_SUCCESS){ 
            ckvs_close(&ckvs);
            return ERR_IO;
        }
    }

    // calculate the master_key (which will be stored in mr), used to encrypt/decrypt msgs in the database
    int err_master_k = ckvs_client_compute_masterkey(&mr, &k_out->c2);
    if(err_master_k != ERR_NONE){ 
        ckvs_close(&ckvs);
        return err_master_k;
    }

    // move cursor in the file to where the value corresponding to entry is located
    int err_seek = fseek(ckvs.file, (long int) k_out->value_off, SEEK_SET);
    if(err_seek != ERR_NONE){ 
        ckvs_close(&ckvs);
        return ERR_IO;
    }

    // length is either the size of value already located in entry (GET)
    // or the length of the value we want to store (SET)
    size_t out_len = set_value == NULL ? k_out->value_len : strlen(set_value)+1;
    out_len += EVP_MAX_BLOCK_LENGTH;

    //unsigned char buffer_out[out_len];
    unsigned char* buffer_out = calloc(out_len, sizeof(unsigned char));

    // --------- GET ---------
    if(set_value == NULL) {

        unsigned char* buffer_in = calloc(k_out->value_len, sizeof(unsigned char));

        if(k_out->value_len == 0){
            free_buffer(buffer_in);
            free_buffer(buffer_out);
            ckvs_close(&ckvs);
            return ERR_NO_VALUE;
        }

        // read the value (pointed to with cursor thanks to previous fseek) from the file
        size_t read = fread(buffer_in, sizeof(unsigned char), k_out->value_len,  ckvs.file);
        if (read != k_out->value_len) {
            free_buffer(buffer_in);
            free_buffer(buffer_out);
            ckvs_close(&ckvs);
            return ERR_IO;
        }

        // decrypt the value
        int decrypt = ckvs_client_crypt_value(&mr, DECRYPT, buffer_in, k_out->value_len,
                                            buffer_out, &out_len);
        if (decrypt != ERR_NONE) {
            free_buffer(buffer_in);
            free_buffer(buffer_out);
            ckvs_close(&ckvs);
            return decrypt;
        }

        // print the value !
        pps_printf("%s\n", buffer_out);

        //free pointer
        free_buffer(buffer_in);
        free_buffer(buffer_out);
    }
    // --------- SET ---------
    else {
        // encrypt "set_value"
        int encrypt = ckvs_client_crypt_value(&mr, ENCRYPT, set_value, strlen(set_value)+1, buffer_out, &out_len);
        if (encrypt != ERR_NONE) {
            free_buffer(buffer_out);
            ckvs_close(&ckvs);
            return encrypt;
        }

        // set new encrypted "set_value" in database
        int write = ckvs_write_encrypted_value(&ckvs, k_out, buffer_out, out_len);
        if (write != ERR_NONE) {
            free_buffer(buffer_out);
            ckvs_close(&ckvs);
            return ERR_IO;
        }

        free_buffer(buffer_out);
    }

    // close database file
    ckvs_close(&ckvs);

    return ERR_NONE;
}

int ckvs_local_get(const char *filename, int optargc, char* optargv[]){

    int check = check_args(optargc, ARG_GET);
    if(check != 0){ return check; }

    const char* key = optargv[0];
    const char* pwd = optargv[1];
    return ckvs_local_getset(filename, key, pwd, NULL);
}

int ckvs_local_set(const char *filename, int optargc, char* optargv[]){

    M_REQUIRE_NON_NULL(filename);
    M_REQUIRE_NON_NULL(optargv);

    int check = check_args(optargc, ARG_SET);
    if(check != 0){ return check; }

    const char* key = optargv[0];
    const char* pwd = optargv[1];
    const char* valuefilename = optargv[2];

    char* buffer;
    size_t b_size = 0;

    // read content of valuefilename and store it in buffer
    int err = read_value_file_content(valuefilename, &buffer, &b_size);
    if (err != ERR_NONE){ return err; }

    // the content in buffer is the new value we'd like to store at the corresponding entry
    err = ckvs_local_getset(filename, key, pwd, buffer);

    free(buffer);
    buffer = NULL;

    return err;
}


int ckvs_local_new(const char *filename, int optargc, char* optargv[]) {

    int check = check_args(optargc, ARG_NEW);
    if(check != 0){ return check; }

    const char* key = optargv[0];
    const char* pwd = optargv[1];

    CKVS_t ckvs;
    int err_open = ckvs_open(filename, &ckvs);
    if(err_open != ERR_NONE){ 
        ckvs_close(&ckvs);
        return err_open; }

    // generates the stretched_key, auth_key and c1 and stores them in mr
    ckvs_memrecord_t mr;
    int err_pwd = ckvs_client_encrypt_pwd(&mr, key, pwd);
    if(err_pwd != ERR_NONE) { 
        ckvs_close(&ckvs);
        return err_pwd; }

    // the new entry we would like to add to the database
    ckvs_entry_t new_entry;
    memset(&new_entry, 0, sizeof(ckvs_entry_t));

    int err_new = ckvs_new_entry(&ckvs, key, &mr.auth_key, &new_entry);
    if(err_new != ERR_NONE) {
        ckvs_close(&ckvs);
        return err_new;
    }
    return ERR_NONE;
}