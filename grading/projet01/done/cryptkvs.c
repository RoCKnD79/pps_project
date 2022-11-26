/*
 * cryptkvs -- main ; argument parsing and dispatch ; etc.
 */

#include <stdio.h>
#include "error.h"
#include "ckvs_local.h"
#include "ckvs_utils.h"

#define ARG_GET 5
#define ARG_SET 6

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
        pps_printf("- cryptkvs <database> stats\n");
        pps_printf("- cryptkvs <database> get <key> <password>\n");
        pps_printf("- cryptkvs <database> set <key> <password> <filename>\n");
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

    // cryptkvs <database> stats
    if(strcmp("stats", cmd) == 0){ 
        return ckvs_local_stats(db_filename); 
    }
    // cryptkvs <database> get <key> <password>
    else if (strcmp("get", cmd) == 0) {
        if(argc == ARG_GET) {
            return ckvs_local_get(argv[1], argv[3], argv[4]);
        } else {
            return check_args(argc, ARG_GET);
        }
    // cryptkvs <database> set <key> <password> <filename>
    }else if(strcmp("set", cmd) == 0){
        if(argc == ARG_SET) {
            return ckvs_local_set(argv[1], argv[3], argv[4], argv[5]);
        }else{
            return check_args(argc, ARG_SET);
        }
    }
    else{ return ERR_INVALID_COMMAND; }
}

/**
 * @brief : just to check the number of arguments
 *
 * @param argc : number of given arguments
 * @param arg_cmd : the number of arguments needed
 * @return : an error message
 */

int check_args(int argc, int arg_cmd){
    if(argc < arg_cmd){
        return ERR_NOT_ENOUGH_ARGUMENTS;
    }else{
        return ERR_TOO_MANY_ARGUMENTS;
    }
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
