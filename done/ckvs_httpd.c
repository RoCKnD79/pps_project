/**
 * @file ckvs_httpd.c
 * @brief webserver
 *
 * @author Edouard Bugnion
 */

#include "ckvs.h"
#include "ckvs_io.h"
#include "ckvs_utils.h"
#include "error.h"
#include "ckvs_httpd.h"
#include <assert.h>
#include "mongoose.h"
#include <json-c/json.h>
#include <string.h>
#include <assert.h>
#include <curl/curl.h>
#include "util.h"
#include <stdbool.h>
#include "libmongoose/mongoose.h"


// Handle interrupts, like Ctrl-C
static int s_signo;

#define ERR_SHA_FROM_STRING -1

#define HTTP_ERROR_CODE 500
#define HTTP_OK_CODE 200
#define HTTP_FOUND_CODE 302
#define HTTP_NOTFOUND_CODE 404

#define MONGOOSE_LEN 1024

#define TMP_LEN 5

static void handle_stats_call(struct mg_connection *nc, struct CKVS *ckvs,
                              _unused struct mg_http_message *hm);

static void handle_get_call(struct mg_connection *nc, struct CKVS *ckvs,
                              _unused struct mg_http_message *hm);

static void handle_set_call(struct mg_connection *nc, struct CKVS *ckvs,
                            _unused struct mg_http_message *hm);

static char* get_urldecoded_argument(struct mg_http_message *hm, const char *arg);

void free_ptr(unsigned char** ptr);

/**
 * @brief Sends an http error message
 * @param nc the http connection
 * @param err the error code corresponding the error message
*/
void mg_error_msg(struct mg_connection* nc, int err)
{
    assert(err>=0 && err < ERR_NB_ERR);
    mg_http_reply(nc, HTTP_ERROR_CODE, NULL, "Error: %s", ERR_MESSAGES[err]);
}

/**
 * @brief Handles signal sent to program, eg. Ctrl+C
 */
static void signal_handler(int signo)
{
    s_signo = signo;
}

// ======================================================================
/**
 * @brief Handles server events (eg HTTP requests).
 * For more check https://cesanta.com/docs/#event-handler-function
 */
static void ckvs_event_handler(struct mg_connection *nc, int ev, void *ev_data, void *fn_data)
{
    struct mg_http_message *hm = (struct mg_http_message *) ev_data;
    struct CKVS *ckvs = (struct CKVS*) fn_data;

    if (ev != MG_EV_POLL)
        debug_printf("Event received %d", ev);

    switch (ev) {
    case MG_EV_POLL:
    case MG_EV_CLOSE:
    case MG_EV_READ:
    case MG_EV_WRITE:
    case MG_EV_HTTP_CHUNK:
        break;

    case MG_EV_ERROR:
        debug_printf("httpd mongoose error \n");
        break;
    case MG_EV_ACCEPT:
        // students: no need to implement SSL
        assert(ckvs->listening_addr);
        debug_printf("accepting connection at %s\n", ckvs->listening_addr);
        assert (mg_url_is_ssl(ckvs->listening_addr) == 0);
        break;

    case MG_EV_HTTP_MSG:
    { 
        // TODO: handle commands calls
        if(mg_http_match_uri(hm, "/stats")) { 
            handle_stats_call(nc, ckvs, hm); 
        } else if (mg_http_match_uri(hm, "/get")) {
            handle_get_call(nc, ckvs, hm);
        } else if (mg_http_match_uri(hm, "/set")){
            handle_set_call(nc, ckvs, hm);
        } else {
            mg_error_msg(nc, NOT_IMPLEMENTED);
        }


        break;
    }

    default:
        fprintf(stderr, "ckvs_event_handler %u\n", ev);
        assert(0);
    }
}

// ======================================================================
int ckvs_httpd_mainloop(const char *filename, int optargc, char **optargv)
{
    if (optargc < 1)
        return ERR_NOT_ENOUGH_ARGUMENTS;
    else if (optargc > 1)
        return ERR_TOO_MANY_ARGUMENTS;

    /* Create server */

    signal(SIGINT, signal_handler); //adds interruption signals to the signal handler
    signal(SIGTERM, signal_handler);

    struct CKVS ckvs;
    int err = ckvs_open(filename, &ckvs);

    if (err != ERR_NONE) {
        return err;
    }

    ckvs.listening_addr = optargv[0];
    //ckvs.listening_addr = optargv[3];

    struct mg_mgr mgr;
    struct mg_connection *c;

    mg_mgr_init(&mgr);

    c = mg_http_listen(&mgr, ckvs.listening_addr, ckvs_event_handler, &ckvs);
    if (c==NULL) {
        debug_printf("Error starting server on address %s\n", ckvs.listening_addr);
        ckvs_close(&ckvs);
        return ERR_IO;
    }

    debug_printf("Starting CKVS server on %s for database %s\n", ckvs.listening_addr, filename);

    while (s_signo == 0) {
        mg_mgr_poll(&mgr, 1000); //infinite loop as long as no termination signal occurs
    }
    mg_mgr_free(&mgr);
    ckvs_close(&ckvs);
    debug_printf("Exiting HTTPD server\n");
    return ERR_NONE;
}

static void handle_stats_call(struct mg_connection *nc, struct CKVS *ckvs,
                              _unused struct mg_http_message *hm)
{
    json_object* json = json_object_new_object();

    /* add ckvs header */
    json_object_object_add(json, "header_string", json_object_new_string(ckvs->header.header_string));
    /* add ckvs version */
    json_object_object_add(json, "version", json_object_new_int(ckvs->header.version));
    /* add ckvs table size */
    uint32_t table_size = ckvs->header.table_size;
    json_object_object_add(json, "table_size", json_object_new_int(table_size));
    /* add ckvs threshold number of entries */
    json_object_object_add(json, "threshold_entries", json_object_new_int(ckvs->header.threshold_entries));
    /* add ckvs number of entries */
    json_object_object_add(json, "num_entries", json_object_new_int(ckvs->header.num_entries));
    /* add the array of actual entries */
    json_object* keys = json_object_new_array();
    for(int i = 0; i < table_size; ++i) {
        if(strlen(ckvs->entries[i].key) != 0) {
            json_object_array_add(keys, json_object_new_string(ckvs->entries[i].key));
        }
    }
    json_object_object_add(json, "keys", keys);

    const char* json_string = json_object_to_json_string(json);
    mg_http_reply(nc, HTTP_OK_CODE, "Content-Type: application/json\r\n", "%s\n", json_string);
    
    json_object_put(json);
}

static void handle_get_call(struct mg_connection *nc, struct CKVS *ckvs,
                              _unused struct mg_http_message *hm) 
{

    if(nc == NULL) return;

    if(ckvs == NULL){
        mg_error_msg(nc, ERR_IO);
        return;
    }

    //key decoded
    char* key_dec = get_urldecoded_argument(hm, "key");
    if(key_dec == NULL) {
        mg_error_msg(nc, ERR_INVALID_ARGUMENT);
        curl_free(key_dec);
        return;
    }

    //auth-key encoded
    char buf[SHA256_PRINTED_STRLEN];
    int err_get_var = mg_http_get_var(&hm->query, "auth_key", buf, MONGOOSE_LEN);
    if(err_get_var <= 0) {
        mg_error_msg(nc, ERR_IO);
        curl_free(key_dec);
        return;
    }

    //auth_key decoded
    ckvs_sha_t auth_key;
    memset(&auth_key, 0, sizeof(ckvs_sha_t));
    int err_sha = SHA256_from_string(buf, &auth_key);
    if(err_sha == ERR_SHA_FROM_STRING) { 
        mg_error_msg(nc, ERR_SHA_FROM_STRING);
        curl_free(key_dec);
        return;
    }

    //retrieving the entry
    ckvs_entry_t* k_out = NULL;
    int err_key = ckvs_find_entry(ckvs, key_dec, &auth_key, &k_out);
 
    if(err_key != ERR_NONE){
        mg_error_msg(nc, err_key);
        curl_free(key_dec);
        return;
    }

    if(k_out == NULL){
        mg_error_msg(nc, ERR_NO_VALUE);
        curl_free(key_dec);
        return;
    }

    if(k_out->value_len == 0) {
        mg_error_msg(nc, ERR_NO_VALUE);
        curl_free(key_dec);
        return;
    }

    //creation of a json object
    json_object* json = json_object_new_object();

    //placing the cursor to read the data
    int err_seek = fseek(ckvs->file, (long int) k_out->value_off, SEEK_SET);
    if(err_seek != ERR_NONE){
        mg_error_msg(nc, ERR_IO);
        curl_free(key_dec);
        json_object_put(json);
        return;
    }

    //buffer allocation
    unsigned char* data = calloc(k_out->value_len, sizeof(unsigned char));
    if(data == NULL) {
        mg_error_msg(nc, ERR_OUT_OF_MEMORY);
        curl_free(key_dec);
        json_object_put(json);
        free_ptr(&data);
        return;
    }

    if(k_out->value_len == 0){
        mg_error_msg(nc, ERR_IO);
        curl_free(key_dec);
        json_object_put(json);
        free_ptr(&data);
        return;
    }

    //lecture de la data
    size_t err_read = fread(data, sizeof(unsigned char), k_out->value_len,  ckvs->file);
    if (err_read != k_out->value_len) {
        mg_error_msg(nc, ERR_IO);
        curl_free(key_dec);
        json_object_put(json);
        free_ptr(&data);
        return;
    }

    //encrypting c2
    char c2_encoded[SHA256_PRINTED_STRLEN];
    SHA256_to_string(&(k_out->c2), c2_encoded);

    //data encryption
    unsigned char* data_encoded = calloc(k_out->value_len*2+1, sizeof(unsigned char));
    hex_encode(data, k_out->value_len,data_encoded);

    //adding to JSON
    json_object_object_add(json, "c2", json_object_new_string(c2_encoded));
    json_object_object_add(json, "data", json_object_new_string(data_encoded));

    //sending reply
    const char* json_string = json_object_to_json_string(json);
    mg_http_reply(nc, HTTP_OK_CODE, "Content-Type: application/json\r\n", "%s\n", json_string);

    //freeing memory
    free_ptr(&data_encoded);
    free_ptr(&data);
    curl_free(key_dec);
    json_object_put(json);
}

static void handle_set_call(struct mg_connection *nc, struct CKVS *ckvs,
                            _unused struct mg_http_message *hm)
{
    if(nc == NULL) return;
    if(ckvs == NULL){
        mg_error_msg(nc, ERR_IO);
        return;
    }

    //chunks collection
    if(hm->body.len > 0) {
        int ret = mg_http_upload(nc, hm, "/tmp");
        if(ret < 0) mg_error_msg(nc, ERR_IO);
        return;
    }
    
    //key retrieval
    char* key = get_urldecoded_argument(hm, "key");
    if(key == NULL) {
        mg_error_msg(nc, ERR_INVALID_ARGUMENT);
        curl_free(key);
        return;
    }
    
    //auth-key encoded
    char buf[SHA256_PRINTED_STRLEN];
    int err_get_var = mg_http_get_var(&hm->query, "auth_key", buf, MONGOOSE_LEN);
    if(err_get_var <= 0) {
        mg_error_msg(nc, ERR_IO);
        curl_free(key);
        return;
    }

    //auth-key decoded
    ckvs_sha_t auth_key;
    memset(&auth_key, 0, sizeof(ckvs_sha_t));
    int err_sha = SHA256_from_string(buf, &auth_key);
    if(err_sha == ERR_SHA_FROM_STRING) { //le type d'erreur provenant de sha from string est -1
        mg_error_msg(nc, ERR_SHA_FROM_STRING);
        curl_free(key);
        return;
    }

    //entry retrieval
    ckvs_entry_t* k_out;
    int err_key = ckvs_find_entry(ckvs, key, &auth_key, &k_out);
    if(err_key != ERR_NONE){
        mg_error_msg(nc, err_key);
        free(key);
        return;
    }

    const char* name = get_urldecoded_argument(hm, "name");
    if(name == NULL){
        mg_error_msg(nc, ERR_INVALID_ARGUMENT);
        curl_free(key);
        curl_free(name);
        return;
    }

    // reading temporary file /tmp/<name>
    char* filename = calloc(TMP_LEN + strlen(name) + 1, sizeof(char));
    strcpy(filename, "/tmp/");
    strcat(filename, name);
    char* buffer;
    size_t b_size = 0;

    int err = read_value_file_content(filename, &buffer, &b_size);
    if (err != ERR_NONE){
        mg_error_msg(nc, err);
        curl_free(key);
        curl_free(name);
        free(filename);
        free(buffer);
        return;
    }
    free(filename);

    // reading json values
    json_object* json = json_tokener_parse(buffer);
    if(json == NULL) {
        mg_error_msg(nc, ERR_IO);
        curl_free(key);
        curl_free(name);
        free(buffer);
        M_EXIT(ERR_IO, "%s", "json_tokener_parse() failed");
    }
    free(buffer);

    json_object* cc_json;
    json_bool exists = json_object_object_get_ex(json, "c2", &cc_json);
    if (exists == 0) { 
        mg_error_msg(nc, ERR_IO);
        json_object_put(json);
        curl_free(key);
        curl_free(name);
        return;
    }

    const char* cc_temp = json_object_get_string(cc_json);
    ckvs_sha_t cc = {"\0"};
    SHA256_from_string(cc_temp, &cc);
    k_out->c2 = cc;

    json_object* data_json;
    exists = json_object_object_get_ex(json, "data", &data_json);
    if (exists == 0) {
        mg_error_msg(nc, ERR_IO);
        json_object_put(json);
        curl_free(key);
        curl_free(name);
        return;
    }

    const char* hex_data = json_object_get_string(data_json);
    size_t len = (strlen(hex_data))/2;

    const unsigned char* data = calloc(len, sizeof(unsigned char));

    // hex decode the data
    size_t len_bytes = hex_decode(hex_data, data);
    size_t outbuflen = 0;

    int err_write = ckvs_write_encrypted_value(ckvs, k_out, data, len);
    if (err_write != ERR_NONE) {
        mg_error_msg(nc, err_write);
        curl_free(key);
        curl_free(name);
        free_ptr(&data);
        json_object_put(json);
        return;
    }

    mg_http_reply(nc, HTTP_OK_CODE, "", "");

    curl_free(key);
    curl_free(name);
    free_ptr(&data);
    json_object_put(json);
}

static char* get_urldecoded_argument(struct mg_http_message *hm, const char *arg)
{
    char buf[MONGOOSE_LEN];
    int err = mg_http_get_var(&hm->query, arg, buf, MONGOOSE_LEN);
    if(err <= 0) M_EXIT(NULL, "%s", "http_get_var failed");

    CURL *curl = curl_easy_init();
    int outlen;
    char* url_decoded = curl_easy_unescape(curl, buf, MONGOOSE_LEN, &outlen);

    curl_easy_cleanup(curl);
    if(url_decoded == NULL) M_EXIT(NULL, "%s", "curl_easy_unescape() failed");

    return url_decoded;
}

void free_ptr(unsigned char** ptr){
    if(ptr == NULL) return;

    free(*ptr);
    *ptr = NULL;
}