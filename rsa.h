#ifndef _RSA_H_
#define _RSA_H_

#include "rsa_num.h"
#include "rsa_util.h"

#define ARG "arg"
#define RSA_SIGNITURE "IASRSA"
#define RSA_KEYLINK_PREFIX "key"
#define RSA_ENCRYPTION_LEVEL_DEFAULT 128
#define RSA_KEY_TYPE_PRIVATE 1<<0
#define RSA_KEY_TYPE_PUBLIC 1<<1
#define RSA_KEY_DATA_QUICK 1<<5
#define RSA_KEY_DATA_FULL 1<<6
#define BUF_LEN_UNIT_QUICK 1024
#define BUF_LEN_UNIT_FULL 128

#define  MIN(x, y) ((x) < (y) ? (x) : (y))

#define	RSA_TBD(msg) printf("TBD: %s\n", (msg))
#define OPT_FLAG(OPT) (1 << (OPT))

#define OPT_ADD(flags, OPT) \
    do { \
	if (*(flags) & OPT_FLAG(OPT)) \
	{ \
	    rsa_error_message(RSA_ERR_ARGREP); \
	    return -1; \
	} \
	*(flags) |= OPT_FLAG(OPT); \
    } \
    while (0)
     
typedef enum {
    /* actions */
    RSA_OPT_HELP,
    RSA_OPT_KEY_SCAN,
    RSA_OPT_KEY_SET_DEFAULT,
    RSA_OPT_KEY_SET_DYNAMIC,
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
    RSA_OPT_ENC_INFO_ONLY,
    RSA_OPT_ORIG_FILE,
    RSA_OPT_MAX
} rsa_opt_t;

typedef struct opt_t {
    int code;
    char short_opt;
    char *long_opt;
    int arg_required;
    char *description;
} opt_t;

typedef struct {
    char keytype;
    opt_t *options;
    int (* ops_handler)(int code, int *flags);
    int (* ops_handler_finalize)(int *flags, int actions);
} rsa_handler_t ;

typedef struct rsa_key_t {
    struct rsa_key_t *next;
    char type;
    char name[KEY_DATA_MAX_LEN];
    char path[MAX_FILE_NAME_LEN];
    FILE *file;
    u1024_t n;
    u1024_t exp;
} rsa_key_t;

extern char key_data[KEY_DATA_MAX_LEN];
extern char file_name[MAX_FILE_NAME_LEN];
extern char newfile_name[MAX_FILE_NAME_LEN + 4];
extern int rsa_encryption_level;
extern int is_encryption_info_only;
extern int file_size;
extern int keep_orig_file;

int opt_short2code(opt_t *options, int opt);
int parse_args(int argc, char *argv[], int *flags, rsa_handler_t *handler);
int rsa_error(char *app);
int rsa_set_file_name(char *name);
rsa_opt_t rsa_action_get(int flags, ...);
int rsa_action_handle_common(rsa_opt_t action, char *app, 
    rsa_handler_t *handler);
char *key_path_get(void);
int rsa_set_key_name(char *name);
int rsa_set_key_data(char *name);
rsa_key_t *rsa_key_open(char accept);
void rsa_key_close(rsa_key_t *key);
int rsa_key_enclev_set(rsa_key_t *key, int new_level);
int rsa_encryption_level_set(char *optarg);
void rsa_encode(u1024_t *res, u1024_t *data, u1024_t *exp, u1024_t *n);
void rsa_decode(u1024_t *res, u1024_t *data, u1024_t *exp, u1024_t *n);
#endif
