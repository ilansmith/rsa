#ifndef _RSA_H_
#define _RSA_H_

#include "rsa_num.h"
#include "rsa_util.h"

#define RSA_SIGNITURE "IASRSA"
#define RSA_KEYLINK_PREFIX "key"
#define MAX_FILE_NAME_LEN 256
#define RSA_KEY_TYPE_PRIVATE 1<<0
#define RSA_KEY_TYPE_PUBLIC 1<<1

#define	RSA_TBD(msg) printf("TBD: %s\n", (msg))
#define OPT_FLAG(OPT) (1 << (OPT))

#define OPT_ADD(flags, OPT, ...) { \
    do { \
	if (*(flags) & OPT_FLAG(OPT)) \
	    return RSA_ERR_ARGREP; \
	*(flags) |= OPT_FLAG(OPT), \
	##__VA_ARGS__; \
    } while (0); \
}
     
typedef enum {
    /* actions */
    RSA_OPT_HELP,
    RSA_OPT_SCANKEYS,
    RSA_OPT_SETKEY,
    RSA_OPT_PATH,
    RSA_OPT_QUITE,
    RSA_OPT_VERBOSE,
    RSA_OPT_ENCRYPT,
    RSA_OPT_DECRYPT,
    RSA_OPT_KEYGEN,
    /* non actions */
    RSA_OPT_LEVEL,
    RSA_OPT_RSAENC,
    RSA_OPT_FILE,
#if 0
    RSA_OPT_PATH,
    RSA_OPT_STDIN,
#endif
    RSA_OPT_MAX
} rsa_opt_t;

typedef struct opt_t {
    int code;
    char short_opt;
    char *long_opt;
    int arg_requirement;
    char *description;
} opt_t;

typedef struct {
    char keytype;
    opt_t *options;
    rsa_errno_t (* ops_handler)(int code, int *flags);
    rsa_errno_t (* ops_handler_finalize)(int *flags, int actions);
} rsa_handler_t ;

extern char key_id[KEY_ID_MAX_LEN];

int opt_short2code(opt_t *options, int opt);
rsa_errno_t parse_args(int argc, char *argv[], int *flags, 
    rsa_handler_t *handler);
int rsa_error(char *app, rsa_errno_t err);
int rsa_set_file_name(char *name);
rsa_opt_t rsa_action_get(int flags, ...);
int rsa_action_handle_common(rsa_opt_t action, char *app, 
    rsa_handler_t *handler);
char *key_path_get(void);
int rsa_set_key_id(char *id);
int rsa_encryption_level_set(char *optarg);
void rsa_encode(u1024_t *res, u1024_t *data, u1024_t *exp, u1024_t *n);
void rsa_decode(u1024_t *res, u1024_t *data, u1024_t *exp, u1024_t *n);
#endif
