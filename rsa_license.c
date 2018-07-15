#include <stdlib.h>
#include <stdio.h>
#if defined(__linux__)
#include <sys/time.h>
#endif
#include <sys/stat.h>
#include "rsa_stream.h"
#include "rsa_num.h"
#include "rsa_crc.h"
#include "rsa_license.h"

#define SEED_ENCRYPTION_LEVEL 512

static void xor_user_data(char *buf, int len)
{
	int i;

	for (i = 0; i < len; i++)
		buf[i] ^= (char)RSA_RANDOM();
}

/* 
 * License file format:
 *
 * +----------+----------------------------------+--------------+
 * | Type     | Semantic                         | Encryption   |
 * +----------+----------------------------------+--------------+
 * | u1024_t  | random seed                      | RSA (512bit) |
 * | u64      | user specific data crc encrypted | Xor with RNG |
 * | size_t   | user specific data length        | Xor with RNG |
 * | u64[]    | user specific data...            | Xor with RNG |
 * +----------+----------------------------------+--------------+
 */
int rsa_license_create(struct rsa_stream_init *stream_init_priv_key,
		char *file_name, struct rsa_license_ops *license_ops,
		void *data)
{
	rsa_stream_t *ciphertext = NULL;
	struct rsa_stream_init init;
	rsa_key_t *key = NULL;
	int ret = -1;
	char *buf = NULL;
	u64 crc;
	size_t len;
	size_t len_enc = 0;

	/* setup extra data */
	if (!license_ops->lic_create ||
			license_ops->lic_create(&buf, &len, data)) {
		return -1;
	}

	/* open file */
	init.type = RSA_STREAM_TYPE_FILE;
	init.params.file.path = file_name;
	init.params.file.mode = "w+b";
	if (!(ciphertext = sopen(&init)))
		goto exit;

	/* open private key */
	key = rsa_key_open(stream_init_priv_key, RSA_KEY_TYPE_PRIVATE, 1);
	if (!key)
		goto exit;

	/* RSA encrypt random seed */
	if (rsa_encrypt_seed(key, ciphertext))
		goto exit;

	/* XoR encrypt crc */
	crc = rsa_crc(buf, len);
	crc ^= (u64)RSA_RANDOM();

	/* XoR encrypt user data length */
	len_enc = len ^ (size_t)RSA_RANDOM();

	/* XoR encrypt user data */
	xor_user_data(buf, len);

	/* write crc to license file */
	if (swrite(&crc, sizeof(size_t), 1, ciphertext) != 1)
		goto exit;

	/* write len_enc to license file */
	if (swrite(&len_enc, sizeof(u64), 1, ciphertext) != 1)
		goto exit;

	/* write user encrypted data to license file */
	if (swrite(buf, sizeof(char), len, ciphertext) != len)
		goto exit;

	ret = 0;

exit:
	/* close file */
	if (ciphertext)
		sclose(ciphertext);

	/* close private key */
	rsa_key_close(key);

	/* on error remove file */
	if (ret)
		remove(file_name);

	/* cleanup buf */
	free(buf);

	return ret;
}

static int rsa_license_get(struct rsa_stream_init *pub_key_stream_init,
		char *file_name, char **buf, int *len)
{
	rsa_stream_t *ciphertext;
	struct rsa_stream_init init;
	char c;
	rsa_key_t *key = NULL;
	u1024_t seed;
	u64 crc;
	int ret = -1;
	char *_buf;
	int _len;

	/* open file */
	init.type = RSA_STREAM_TYPE_FILE;
	init.params.file.path = file_name;
	init.params.file.mode = "rb";
	if (!(ciphertext = sopen(&init)))
		goto exit;

	/* open private key */
	key = rsa_key_open(pub_key_stream_init, RSA_KEY_TYPE_PUBLIC, 1);
	if (!key)
		goto exit;

	rsa_key_enclev_set(key, rsa_encryption_level);

	/* extract seed */
	rsa_read_u1024_full(ciphertext, &seed);

	/* decode seed */
	rsa_decode(&seed, &seed, &key->exp, &key->n);

	/* initialize rng with seed */
	if (number_seed_set_fixed(&seed))
		goto exit;

	/* read crc from license */
	if (sread(&crc, sizeof(u64), 1, ciphertext) != 1)
		goto exit;

	/* XoR decrypt crc */
	crc ^= (u64)RSA_RANDOM();

	/* read len from license */
	if (sread(&_len, sizeof(size_t), 1, ciphertext) != 1)
		goto exit;

	/* XoR decrypt len */
	_len ^= (u64)RSA_RANDOM();

	/* allocate buffer for user data */
	if (!(_buf = (char*)calloc(_len, sizeof(char))))
		goto exit;

	/* read user data from license and assert no excess data */
	if (sread(_buf, sizeof(char), _len, ciphertext) != _len ||
			0 < sread(&c, sizeof(char), 1, ciphertext)) {
		goto exit;
	}

	/* XoR decrypt user data */
	xor_user_data(_buf, _len);

	/* check crc */
	if (crc == rsa_crc(_buf, _len)) {
		*buf = _buf;
		*len = _len;
		ret = 0;
	}

exit:
	/* close file */
	if (ciphertext)
		sclose(ciphertext);

	/* close private key */
	rsa_key_close(key);

	return ret;
}

int rsa_license_info(struct rsa_stream_init *pub_key_stream_init,
		char *file_name, struct rsa_license_ops *license_ops)
{
	char *buf = NULL;
	int len;
	int ret = -1;

	if (!license_ops->lic_info)
		return -1;

	if (rsa_license_get(pub_key_stream_init, file_name, &buf, &len))
		goto exit;

	license_ops->lic_info(buf, len);

	ret = 0;

exit:
	free(buf);
	return ret;
}

int rsa_license_extract(struct rsa_stream_init *pub_key_stream_init,
		char *file_name, struct rsa_license_ops *license_ops,
		void *data)
{
	char *buf = NULL;
	int len;
	int ret = -1;

	if (!license_ops->lic_extract)
		return -1;

	if (rsa_license_get(pub_key_stream_init, file_name, &buf, &len))
		goto exit;

	license_ops->lic_extract(buf, len, data);

	ret = 0;

exit:
	free(buf);
	return ret;
}

void rsa_license_init(void)
{
	rsa_encryption_level = SEED_ENCRYPTION_LEVEL;
}

