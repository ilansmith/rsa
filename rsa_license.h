#ifndef _RSA_LICENSE_H_
#define _RSA_LICENSE_H_

#include "rsa_stream.h"
#include "rsa_num.h"
#include "rsa_util.h"

struct rsa_license_ops {
	int (*lic_create)(char **buf, size_t *len, void *data);
	int (*lic_info)(char *buf, size_t len);
	int (*lic_extract)(char *buf, size_t len, void *data);
};

int rsa_license_create(struct rsa_stream_init *stream_init_priv_key,
		char *file_name, struct rsa_license_ops *license_ops,
		void *data);
int rsa_license_info(struct rsa_stream_init *pub_key_stream_init,
		char *file_name, struct rsa_license_ops * license_ops);
int rsa_license_extract(struct rsa_stream_init *pub_key_stream_init,
		char *file_name, struct rsa_license_ops *license_ops,
		void *data);

void rsa_license_init(void);

#endif

