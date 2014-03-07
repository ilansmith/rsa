#ifndef _RSA_H_
#define _RSA_H_

#if 0
#define RSA_MASTER (!defined(RSA_ENC) && !defined(RSA_DEC))
#define RSA_ENCRYPTER (!defined(RSA_DEC) && !RSA_MASTER)
#define RSA_DECRYPTER (!defined(RSA_ENC) && !RSA_MASTER)
#endif

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
    RSA_OPT_VENDOR,
    RSA_OPT_SCANKEY,
    RSA_OPT_SETKEY,
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

typedef enum {
    RSA_ERR_NONE,
    RSA_ERR_ARGREP,
    RSA_ERR_NOACTION,
    RSA_ERR_MULTIACTION,
    RSA_ERR_NOFILE,
    RSA_ERR_OPTARG,
    RSA_ERR_INTERNAL
} rsa_errno_t;

typedef struct opt_t {
    int code;
    char short_opt;
    char *long_opt;
    int arg_requirement;
    char *description;
} opt_t;

typedef struct {
    opt_t *options;
    rsa_errno_t (* ops_handler)(int code, int *flags);
    rsa_errno_t (* ops_handler_finalize)(int *flags, int actions);
} rsa_handler_t ;

rsa_errno_t parse_args(int argc, char *argv[], int *flags, 
    rsa_handler_t *handler);
int rsa_error(char *app, rsa_errno_t err);
int opt_short2code(opt_t *options, int opt);
int rsa_set_file_name(char *name);
rsa_opt_t rsa_action_get(int flags, ...);
int rsa_action_handle_common(rsa_opt_t action, char *app, 
    opt_t *options_private);
#endif
