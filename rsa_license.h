#ifndef _RSA_LICENSE_H_
#define _RSA_LICENSE_H_

#include "rsa_num.h"
#include "rsa_util.h"

typedef int (*lic_create_t)(char *buf, int len, void *data);
typedef int (*lic_parse_t)(char *buf, int len);
typedef int (*lic_extract_t)(char *buf, int len, void *data);

struct rsa_license_ops {
	lic_create_t lic_create;
	lic_parse_t lic_parse;
	lic_extract_t lic_extract;
};

#define ARG "arg"

#define	RSA_TBD(msg) printf("TBD: %s\n", (msg))
#define OPT_FLAG(OPT) (1 << (OPT))

#define OPT_ADD(flags, OPT) do { \
	if (*(flags) & OPT_FLAG(OPT)) { \
		rsa_error_message(RSA_ERR_ARGREP); \
		return -1; \
	} \
	*(flags) |= OPT_FLAG(OPT); \
} while (0)

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
	RSA_OPT_CBC,
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
	int (*ops_handler)(int code, unsigned int *flags);
	int (*ops_handler_finalize)(unsigned int *flags, int actions);
} rsa_handler_t ;

int rsa_license_create(char *priv_key_path, char *file_name, 
		struct rsa_license_ops *license_ops, void *data);
int rsa_license_info(char *pub_key_path, char *file_name,
		struct rsa_license_ops * license_ops);
void rsa_license_init(void);

#endif

