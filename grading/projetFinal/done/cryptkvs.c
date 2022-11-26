/*
 * cryptkvs -- main ; argument parsing and dispatch ; etc.
 */

#include <stdio.h>
#include "error.h"
#include "ckvs_local.h"
#include "ckvs_utils.h"
#include "ckvs_client.h"
#include "ckvs_httpd.h"

#define HTTP_SIZE 7
#define HTTPS_SIZE 8

typedef int (*ckvs_command)(const char*, int, char* []);

typedef struct {
    const ckvs_command cmd_remote;
    const ckvs_command cmd_local;
    const char* nom;
    const char* dsc; //description
} ckvs_command_mapping;

const static ckvs_command_mapping commands[5] = {
    { ckvs_client_stats, ckvs_local_stats, "stats", "- cryptkvs [<database>|<URL>] stats\n" },
    { ckvs_client_get, ckvs_local_get,   "get",   "- cryptkvs [<database>|<URL>] get <key> <password>\n" },
    { ckvs_client_set, ckvs_local_set,   "set",   "- cryptkvs [<database>|<URL>] set <key> <password> <filename>\n" },
    { ckvs_client_new, ckvs_local_new,   "new",   "- cryptkvs [<database>|<URL>] new <key> <password>\n" },

    { ckvs_httpd_mainloop, NULL, "httpd", "- cryptkvs <database> httpd <url>\n" }
    };

/* *************************************************** *
 * TODO WEEK 09-11: Add then augment usage messages    *
 * *************************************************** */

/* *************************************************** *
 * TODO WEEK 04-07: add message                        *
 * TODO WEEK 09: Refactor usage()                      *
 * *************************************************** */
static void usage(const char *execname, int err)
{
    if (err == ERR_INVALID_COMMAND) {
        pps_printf("Available commands:\n");
        pps_printf("\n");

        for(int i = 0; i < 5; ++i){ pps_printf("%s\n", commands[i].dsc); }
        
    } else if (err >= 0 && err < ERR_NB_ERR) {
        printf("ERROR %d", err);
        pps_printf("%s exited with error: %s\n\n\n", execname, ERR_MESSAGES[err]);
    } else {
        pps_printf("%s exited with error: %d (out of range)\n\n\n", execname, err);
    }
}

/* *************************************************** *
 * TODO WEEK 04-11: Add more commands                  *
 * TODO WEEK 09: Refactor ckvs_local_*** commands      *
 * *************************************************** */
/**
 * @brief Runs the command requested by the user in the command line, or returns ERR_INVALID_COMMAND if the command is not found.
 *
 * @param argc (int) the number of arguments in the command line
 * @param argv (char*[]) the arguments of the command line, as passed to main()
 */
int ckvs_do_one_cmd(int argc, char *argv[])
{
    if (argc < 3) return ERR_INVALID_COMMAND;

    const char* db_filename = argv[1];
    const char* cmd = argv[2];
    int optargc = argc - 3;

    char** new_argv = argv+3;

    for(int i = 0; i < 4; ++i){
        // verify command (stats, get, set or new)
        if(strcmp(commands[i].nom, cmd) == 0){ 
            // check if URL or local database
            if(strncmp(db_filename, "http://", HTTP_SIZE) == 0  ||   strncmp(db_filename, "https://", HTTPS_SIZE) == 0) {
                return commands[i].cmd_remote(db_filename, optargc, new_argv);
            } else {
                return commands[i].cmd_local(db_filename, optargc, new_argv);
            }
        }
    }   

    // cryptkvs <database> httpd <url>
    if(strcmp(commands[4].nom, cmd) == 0) { // TODO il faut vérifier que la database est une database locale (jsp cmt) --> echo $LD_LIBRARY_PATH ??
        return commands[4].cmd_remote(db_filename, optargc, new_argv);
    }

    return ERR_INVALID_COMMAND;
}

#ifndef FUZZ
/**
 * @brief main function, runs the requested command and prints the resulting error if any.
 */
int main(int argc, char *argv[])
{
    int ret = ckvs_do_one_cmd(argc, argv);
    if (ret != ERR_NONE) {
        usage(argv[0], ret);
    }
    return ret;
}
#endif