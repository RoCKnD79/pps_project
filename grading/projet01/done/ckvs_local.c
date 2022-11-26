#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "ckvs.h"
#include "ckvs_io.h"
#include "ckvs_crypto.h"
#include "openssl/evp.h"
#include "openssl/rand.h"

#define DECRYPT 0
#define ENCRYPT 1
#define RAND_SUCCESS 1

int ckvs_local_stats(const char *filename){
    // open database file, store its contents into ckvs
    CKVS_t ckvs;
    int err_open = ckvs_open(filename, &ckvs);
    if(err_open != ERR_NONE){ return err_open; }

    // display header of database
    print_header(&ckvs.header);

    // print all database entries
    for(int i=0; i < CKVS_FIXEDSIZE_TABLE; ++i){
        if(strlen(ckvs.entries[i].key) > 0){
            print_entry(&ckvs.entries[i]);
        }
    }

    // close database file
    ckvs_close(&ckvs);

    return ERR_NONE;
}

int ckvs_local_getset(const char *filename, const char *key, const char *pwd, const char* set_value){

    M_REQUIRE_NON_NULL(key);
    M_REQUIRE_NON_NULL(pwd);

    // open database file, store its contents into ckvs
    CKVS_t ckvs;
    int err_open = ckvs_open(filename, &ckvs);
    if(err_open != ERR_NONE){ return err_open; }

    // generates the stretched_key, auth_key and c1 and stores them in mr
    ckvs_memrecord_t mr;
    int err_pwd = ckvs_client_encrypt_pwd(&mr, key, pwd);
    if(err_pwd != ERR_NONE) { return err_pwd; }

    // find the entry corresponding to "key"
    ckvs_entry_t* k_out;

    int err_entry = ckvs_find_entry(&ckvs, key, &mr.auth_key, &k_out);
    if(err_entry != ERR_NONE){ return err_entry; }

    // --------- SET ---------
    // generate a new random c2 key
    if(set_value != NULL) {
        int err_rand = RAND_bytes(k_out->c2.sha, SHA256_DIGEST_LENGTH);
        if(err_rand != RAND_SUCCESS){ return ERR_IO;}
    }

    // calculate the master_key (which will be stored in mr), used to encrypt/decrypt msgs in the database
    int err_master_k = ckvs_client_compute_masterkey(&mr, &k_out->c2);
    if(err_master_k != ERR_NONE){ return err_master_k; }

    // move cursor in the file to where the value corresponding to entry is located
    int err_seek = fseek(ckvs.file, (long int) k_out->value_off, SEEK_SET);
    if(err_seek != ERR_NONE){ return ERR_IO; }

    // length is either the size of value already located in entry (GET)
    // or the length of the value we want to store (SET)
    size_t out_len = set_value == NULL ? k_out->value_len : strlen(set_value)+1;
    out_len += EVP_MAX_BLOCK_LENGTH;

    unsigned char buffer_out[out_len];

    // --------- GET ---------
    if(set_value == NULL) {
        // read the value (pointed to with cursor thanks to previous fseek) from the file
        unsigned char buffer_in[k_out->value_len];
        size_t read = fread(&buffer_in, sizeof(unsigned char), k_out->value_len,  ckvs.file);
        if (read != k_out->value_len) { return ERR_IO; }

        // decrypt the value
        int decrypt = ckvs_client_crypt_value(&mr, DECRYPT, buffer_in, k_out->value_len,
                                            buffer_out, &out_len);
        if (decrypt != ERR_NONE) { return decrypt; }

        // print the value !
        pps_printf("%s\n", buffer_out);
    }
    // --------- SET ---------
    else {
        // encrypt "set_value"
        int encrypt = ckvs_client_crypt_value(&mr, ENCRYPT, set_value, strlen(set_value)+1, buffer_out, &out_len);
        if (encrypt != ERR_NONE) { return encrypt; }

        // set new encrypted "set_value" in database
        int write = ckvs_write_encrypted_value(&ckvs, k_out, buffer_out, out_len);
        if (write != ERR_NONE) { return ERR_IO; }
    }
    
    // close database file
    ckvs_close(&ckvs);
    return ERR_NONE;
}

int ckvs_local_get(const char *filename, const char *key, const char *pwd){
    return ckvs_local_getset(filename, key, pwd, NULL);
}

int ckvs_local_set(const char *filename, const char *key, const char *pwd, const char *valuefilename){
    char* buffer;
    size_t b_size = 0;

    // read content of valuefilename and store it in buffer
    int err = read_value_file_content(valuefilename, &buffer, &b_size);
    if (err != ERR_NONE){ return err; }

    // the content in buffer is the new value we'd like to store at the corresponding entry
    err = ckvs_local_getset(filename, key, pwd, buffer);
    free(buffer);

    return err;
}