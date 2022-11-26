#include <stdio.h>
#include <stdbool.h>

#include <json-c/json.h>
#include "openssl/evp.h"

#include "error.h"
#include "ckvs_local.h"
#include "ckvs_client.h"
#include "ckvs_rpc.h"
#include "ckvs_crypto.h"
#include "ckvs.h"
#include "util.h"

#define GET_KEY_EXT 9
#define AUTH_KEY_EXT 10

int ckvs_client_stats(const char *url, int optargc, char **optargv) {

    int check = check_args(optargc, ARG_STATS);
    if(check != 0){ return check; }

    struct ckvs_connection conn; 
    ckvs_rpc_init(&conn, url);

    // stores info from [url]/get?key=<key>&auth_key=<auth_key> into conn.respbuf
    // the variable contains the HTML of the link accessed
    int ret = ckvs_rpc(&conn, "/stats");
    if(ret != ERR_NONE) {
        ckvs_rpc_close(&conn);
        return ret;
    }

    //printf("%s\n", conn.resp_buf);

    //transform the HTML text extracted, into a json_object
    json_object* json = json_tokener_parse(conn.resp_buf);
    if(json == NULL) {
        ckvs_rpc_close(&conn);
        return ERR_INVALID_ARGUMENT;
    }

    /* 
     * the following lines of code extract precise fields of the json_object
     * the extracted fields are each also in the form of json_objects
     * => we transform them into a readable form using json_object_get_string() for ex. 
     * Then we print the value
    */
    json_object* val;
    // get value at field "header_string"
    json_bool exists = json_object_object_get_ex(json, "header_string", &val);
    const char* header = json_object_get_string(val);
    printf("CKVS Header type       : %s\n", header);
    if (exists == 0) {
        json_object_put(json);
        ckvs_rpc_close(&conn);
        return ERR_IO;
    }

    // get value at field "version"
    exists = json_object_object_get_ex(json, "version", &val);
    int32_t version = json_object_get_int(val);
    printf("CKVS Header version    : %d\n", version);
    if (exists == 0) {
        json_object_put(json);
        ckvs_rpc_close(&conn);
        return ERR_IO;
    }

    // get value at field "table_size"
    exists = json_object_object_get_ex(json, "table_size", &val);
    int32_t table_size = json_object_get_int(val);
    printf("CKVS Header table_size : %d\n", table_size);
    if (exists == 0) {
        json_object_put(json);
        ckvs_rpc_close(&conn);
        return ERR_IO;
    }

    // get value at field "threshold_entries"
    exists = json_object_object_get_ex(json, "threshold_entries", &val);
    int32_t thresh_vals = json_object_get_int(val);
    printf("CKVS Header threshold  : %d\n", thresh_vals);
    if (exists == 0) {
        json_object_put(json);
        ckvs_rpc_close(&conn);
        return ERR_IO;
    }

    // get value at field "num_entries"
    exists = json_object_object_get_ex(json, "num_entries", &val);
    int32_t num_entries = json_object_get_int(val);
    printf("CKVS Header num_entries: %d\n", num_entries);
    if (exists == 0) {
        json_object_put(json);
        ckvs_rpc_close(&conn);
        return ERR_IO;
    }

    // get values from the array located at field "keys"
    exists = json_object_object_get_ex(json, "keys", &val);
    if (exists == 0) {
        json_object_put(json);
        ckvs_rpc_close(&conn);
        return ERR_IO;
    }
    size_t keys_len = json_object_array_length(val);
    for(int i = 0; i < keys_len; i++) {
        // get array[idx]
        json_object* json_key = json_object_array_get_idx(val, i);
        // transform json_object of key (json_key) into readable string
        char const* key = json_object_get_string(json_key);
        pps_printf("Key%*s: ", 7, "");
        pps_printf(STR_LENGTH_FMT(CKVS_MAXKEYLEN), key);
        pps_printf("\n");
    }

    int err_json = json_object_put(json);
    if (err_json != 1) return ERR_IO;

    ckvs_rpc_close(&conn);
    return ERR_NONE;
}


int ckvs_client_get(const char *url, int optargc, char **optargv) {
    M_REQUIRE_NON_NULL(url);
    M_REQUIRE_NON_NULL(optargv);

    int check = check_args(optargc, ARG_GET);
    if(check != 0) return check;
    // adapts string to a "url-friendly" version (removes all spaces and weird symbols)
    char* pwd = optargv[1];
    
    //generate stretched_key, c1 and auth_key
    ckvs_memrecord_t mr;
    int err_pwd = ckvs_client_encrypt_pwd(&mr, optargv[0], pwd); //key
    if(err_pwd != ERR_NONE) M_EXIT(err_pwd, "%s", "encrypt_pwd failed");

    char* key = curl_easy_escape(NULL, optargv[0], 0);
    if(key == NULL) M_EXIT(ERR_OUT_OF_MEMORY, "%s", "curl_easy_escape failed");

    const char* url_get = "/get?key=";
    const char* url_auth = "&auth_key=";

    // creating the extension: "/get?key=<key>&auth_key=<auth_key>"
    char* link_extension = calloc(strlen(url_get) + strlen(key) + strlen(url_auth) + SHA256_PRINTED_STRLEN + 1, sizeof(char));
    strncpy(link_extension, url_get, strlen(url_get));
    strncat(link_extension, key, strlen(key));
    strncat(link_extension, url_auth, strlen(url_auth));

    char auth_buf[SHA256_PRINTED_STRLEN];
    // hex_encode the data
    SHA256_to_string(&mr.auth_key, auth_buf);
    strncat(link_extension, auth_buf, SHA256_PRINTED_STRLEN);
    //equivalent to ckvs_open
    struct ckvs_connection conn; 
    int err_init = ckvs_rpc_init(&conn, url);
    if(err_init != ERR_NONE) M_EXIT(err_init, "%s", "ckvs_rpc_int failed");


    // stores info from [url]/get?key=<key>&auth_key=<auth_key> into conn.respbuf
    // the variable contains the HTML of the link accessed
    int ret = ckvs_rpc(&conn, link_extension);
    if(ret != ERR_NONE) {
        curl_free(key);
        free(link_extension);
        ckvs_rpc_close(&conn);

        M_EXIT(ret, "%s", "(ckvs_rpc) connecting to url failed");
    }

    json_object* json = json_tokener_parse(conn.resp_buf);
    if(json == NULL) {
        pps_printf("%s\n", conn.resp_buf);
        curl_free(key);
        free(link_extension);
        ckvs_rpc_close(&conn);

        M_EXIT(ERR_IO, "%s", "json_tokener_parse() failed");
    }

    json_object* val;
    // get value of c2 (given in hex form)
    json_bool exists = json_object_object_get_ex(json, "c2", &val);
    if (exists == 0) {
        json_object_put(json);
        curl_free(key);
        free(link_extension);
        ckvs_rpc_close(&conn);

        return ERR_IO;
    }
    const char* c2_temp = json_object_get_string(val);
    // convert it from hex string to SHA256
    ckvs_sha_t c2 = {"\0"};
    SHA256_from_string(c2_temp, &c2);

    // compute the master_key that will be used to decode 'data'
    int err_master_k = ckvs_client_compute_masterkey(&mr, &c2);
    if(err_master_k != ERR_NONE){ 
        curl_free(key);
        free(c2_temp);
        free(link_extension);
        ckvs_rpc_close(&conn);

        return err_master_k;
    }

    // extract 'data' field from the json object (it is in hex form)
    exists = json_object_object_get_ex(json, "data", &val);
    if (exists == 0) {
        json_object_put(json);
        curl_free(key);
        free(link_extension);
        ckvs_rpc_close(&conn);

        M_EXIT(ERR_IO, "%s", "json obj does not exist");
    }
    const char* hex_data = json_object_get_string(val);
    size_t len = (strlen(hex_data)+1)/2;

    const unsigned char* data = calloc(len+1, sizeof(unsigned char));
    const unsigned char* decrypt = calloc(len + EVP_MAX_BLOCK_LENGTH + 1, sizeof(unsigned char));
    
    // hex decode the data
    size_t len_bytes = hex_decode(hex_data, data);

    size_t outbuflen = 0;
    // decrypt the data using the master_key
    int err_crypt = ckvs_client_crypt_value(&mr, DECRYPT, data, len,
                                            decrypt, &outbuflen);

    pps_printf("%s\n", decrypt);
    if(err_crypt != ERR_NONE) {
        free(decrypt);
        json_object_put(json);
        free(data);
        curl_free(key);
        free(link_extension);
        ckvs_rpc_close(&conn);

        M_EXIT(err_crypt, "%s", "decryption failed");
    }
    int err_json = json_object_put(json);
    if (err_json != 1) return ERR_IO;

    free(decrypt);
    free(data);
    curl_free(key); //necessary after a curl_easy_escape()
    free(link_extension);
    ckvs_rpc_close(&conn);

    return ERR_NONE;
}

int ckvs_client_set(const char *url, int optargc, char **optargv) {
    M_REQUIRE_NON_NULL(url);
    M_REQUIRE_NON_NULL(optargv);

    int check = check_args(optargc, ARG_SET);
    if(check != 0) M_EXIT(check, "%s", "Arguments problem\n");

    char* pwd = optargv[1];

    //generate stretched_key, c1 and auth_key
    ckvs_memrecord_t mr;
    int err_pwd = ckvs_client_encrypt_pwd(&mr, optargv[0], pwd);
    if(err_pwd != ERR_NONE) M_EXIT(err_pwd, "%s", "encrypt_pwd failed\n");

    // adapts string to a "url-friendly" version (removes all spaces and weird symbols)
    char* key = curl_easy_escape(NULL, optargv[0], 0);
    if(key == NULL) M_EXIT(ERR_OUT_OF_MEMORY, "%s", "curl_easy_escape failed\n");

    ckvs_sha_t c_two;

    // --------- SET ---------
    // generate a new random c2 key
    int err_rand = RAND_bytes(c_two.sha, SHA256_DIGEST_LENGTH);
    if(err_rand != RAND_SUCCESS) M_EXIT(ERR_IO, "%s", "Random generator failed\n");

    // calculate the master_key (which will be stored in mr), used to encrypt/decrypt msgs in the database
    int err_master_k = ckvs_client_compute_masterkey(&mr, &c_two);
    if(err_master_k != ERR_NONE) M_EXIT(err_master_k, "%s", "Computation of master-key failed\n");

    //reading file
    const char* valuefilename = optargv[2];

    char* buffer;
    size_t b_size = 0;

    int err = read_value_file_content(valuefilename, &buffer, &b_size);
    if (err != ERR_NONE) M_EXIT(err, "%s", "Read value failed\n");

    // buffer for encryption
    size_t out_len =  b_size + EVP_MAX_BLOCK_LENGTH + 1;
    unsigned char* data = calloc(out_len, sizeof(unsigned char));

    //encryption
    int encrypt = ckvs_client_crypt_value(&mr, ENCRYPT, buffer, b_size,
                                          data, &out_len);

    if (encrypt != ERR_NONE) {
        free(data);
        data = NULL;

        M_EXIT(err_pwd, "%s", "Crypt value failed\n");
    }

    //initialising connection to server
    struct ckvs_connection conn;
    int err_init = ckvs_rpc_init(&conn, url);
    if(err_init != ERR_NONE) M_EXIT(err_init, "%s", "rpc initialisation failed\n");

    const char* set_ext = "/set?name=data.json";
    const char* offset_ext = "&offset=0";
    const char* key_ext = "&key=";
    const char* auth_ext = "&auth_key=";

    // preparing the URL extension
    char* link_extension = calloc(strlen(set_ext) + strlen(offset_ext) + strlen(key_ext)
            + strlen(key) + strlen(auth_ext) + SHA256_PRINTED_STRLEN + 1, sizeof(char));

    strncpy(link_extension, set_ext, strlen(set_ext));

    strncat(link_extension, offset_ext, strlen(offset_ext));

    strncat(link_extension, key_ext, strlen(key_ext));
    strncat(link_extension, key, strlen(key));

    strncat(link_extension, auth_ext, strlen(auth_ext));
    char auth_buf[SHA256_PRINTED_STRLEN];
    // hex_encode the auth_key
    SHA256_to_string(&mr.auth_key, auth_buf);
    strncat(link_extension, auth_buf, SHA256_PRINTED_STRLEN);

    int ret = ckvs_rpc(&conn, link_extension);
    if(ret != ERR_NONE) {
        curl_free(key);
        free(link_extension);
        ckvs_rpc_close(&conn);
        free(data);
        free(buffer);
        M_EXIT(ret, "%s", "(ckvs_rpc) connecting to url failed\n");
    }

    unsigned char* data_hexed = calloc(out_len*2 + 1, sizeof(unsigned char));
    hex_encode(data, out_len, data_hexed);

    char c2_hexed[SHA256_PRINTED_STRLEN];
    SHA256_to_string(&c_two, c2_hexed);

    //creation of the JSON object
    json_object* json = json_object_new_object();

    // adding to the JSON
    json_object_object_add(json, "c2", json_object_new_string(c2_hexed));
    json_object_object_add(json, "data", json_object_new_string(data_hexed));

    int ret_post = ckvs_post(&conn, link_extension, json_object_to_json_string(json));
    if(ret_post != ERR_NONE) {
        free(data_hexed);
        free(link_extension);
        free(data);
        curl_free(key);
        free(buffer);

        json_object_put(json);
        ckvs_rpc_close(&conn);
        
        M_EXIT(ret_post, "%s", "CKVS post failed\n");
    }

    if (conn.resp_buf != NULL) {
        pps_printf("%s\n", conn.resp_buf);
    }

    free(data_hexed);
    free(link_extension);
    free(data);
    curl_free(key);
    free(buffer);

    json_object_put(json);
    ckvs_rpc_close(&conn);

    return ERR_NONE;
}

int ckvs_client_new(const char *url, int optargc, char **optargv) {
    return ERR_NONE;
}