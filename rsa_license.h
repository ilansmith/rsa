#ifndef _RSA_LICENSE_H_
#define _RSA_LICENSE_H_

#include "rsa_num.h"
#include "rsa_util.h"

struct rsa_license_ops {
	int (*lic_create)(char *buf, int len, void *data);
	int (*lic_info)(char *buf, int len);
	int (*lic_extract)(char *buf, int len, void *data);
};

int rsa_license_create(char *priv_key_path, char *file_name, 
		struct rsa_license_ops *license_ops, void *data);
int rsa_license_info(char *pub_key_path, char *file_name,
		struct rsa_license_ops * license_ops);
int rsa_license_extract(char *pub_key_path, char *file_name,
		struct rsa_license_ops *license_ops, void *data);

void rsa_license_init(void);

#endif

