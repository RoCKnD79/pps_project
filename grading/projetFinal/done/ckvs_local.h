/**
 * @file ckvs_local.h
 * @brief ckvs_local -- operations on local databases
 *
 * @author E. Bugnion
 */

#pragma once

#define DECRYPT 0
#define ENCRYPT 1
#define RAND_SUCCESS 1

#define ARG_STATS 0
#define ARG_GET 2
#define ARG_SET 3
#define ARG_NEW 2

/* *************************************************** *
 * TODO WEEK 04                                        *
 * *************************************************** */
/**
 * @brief Opens the CKVS database at the given filename and executes the 'stats' command,
 * ie. prints information about the database.
 * DO NOT FORGET TO USE pps_printf to print the header/entries!!!
 *
 * @param filename (const char*) the path to the CKVS database to open
 * @return int, an error code
 */
int ckvs_local_stats(const char *filename, int optargc, char* optargv[]);

/* *************************************************** *
 * TODO WEEK 05                                        *
 * *************************************************** */
/**
 * @brief Opens the CKVS database at the given filename and executes the 'get' command,
 * ie. fetches, decrypts and prints the entry corresponding to the key and password.
 * DO NOT FORGET TO USE pps_printf to print to value!!!
 *
 * @param filename (const char*) the path to the CKVS database to open
 * @param key (const char*) the key of the entry to get
 * @param pwd (const char*) the password of the entry to get
 * @return int, an error code
 */
int ckvs_local_get(const char *filename, int optargc, char* optargv[]);

/* *************************************************** *
 * TODO WEEK 06                                        *
 * *************************************************** */
/**
 * @brief Opens the CKVS database at the given filename and executes the 'set' command,
 * ie. fetches the entry corresponding to the key and password and
 * then sets the encrypted content of valuefilename as new content.
 *
 * @param filename (const char*) the path to the CKVS database to open
 * @param key (const char*) the key of the entry to set
 * @param pwd (const char*) the password of the entry to set
 * @param valuefilename (const char*) the path to the file which contains what will become the new encrypted content of the entry.
 * @return int, an error code
 */
int ckvs_local_set(const char *filename, int optargc, char* optargv[]);

/**
 * @brief modularisation of the methods get and set
 *
 * @param filename (const char*) the path to the CKVS database to open
 * @param key (const char*) the key of the entry to get
 * @param pwd (const char*) the password of the entry to get
 * @param set_value NULL if we want a "get" and otherwise it is a "set"
 * @return int, an error code
 */
int ckvs_local_getset(const char *filename, const char *key, const char *pwd, const char* set_value);

/* *************************************************** *
 * TODO WEEK 07                                        *
 * *************************************************** */
/**
 * @brief Opens the CKVS database at the given filename and executes the 'new' command,
 * ie. creates a new entry with the given key and password.
 *
 * @param filename (const char*) the path to the CKVS database to open
 * @param key (const char*) the key of the entry to create
 * @param pwd (const char*) the password of the entry to create
 * @return int, an error code
 */
int ckvs_local_new(const char *filename, int optargc, char* optargv[]);

/* *************************************************** *
 * TODO WEEK 09: Refactor ckvs_local_*** commands      *
 * *************************************************** */

/**
 * @brief : just to check the number of arguments
 *
 * @param argc : number of given arguments
 * @param arg_cmd : the number of arguments needed
 * @return : an error message
 */

int check_args(int argc, int arg_cmd);

void free_buffers(unsigned char* buffer_in, unsigned char* buffer_out);