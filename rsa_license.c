#include <stdlib.h>
#include <stdio.h>
#include <sys/time.h>
#include <sys/stat.h>
#include "rsa_stream.h"
#include "rsa_num.h"
#include "rsa_crc.h"
#include "rsa_license.h"

#define LICENSE_LENGTH_MAX 1024
#define LICENSE_LENGTH_USER (LICENSE_LENGTH_MAX - \
	(sizeof(u64) * (16 + 1) + sizeof(u64) * 1))

static void xor_user_data(char *buf, int len)
{
	int i;

	for (i = 0; i < len; i++)
		buf[i] ^= (char)RSA_RANDOM();
}

static u64 xor_encrypt_crc(char *buf, int len)
{
	u64 crc;

	crc = rsa_crc(buf, len);
	return crc ^ (u64)RSA_RANDOM();
}

static u64 xor_decrypt_crc(u64 crc_enc)
{
	return crc_enc ^= (u64)RSA_RANDOM();
}

/* 
 * License file format:
 *
 * +----------+----------------------------------+--------------+
 * | Type     | Semantic                         | Encryption   |
 * +----------+----------------------------------+--------------+
 * | u1024_t  | random seed                      | RSA (512bit) |
 * | u64      | user specific data crc encrypted | Xor with RNG |
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
	char *buf;
	u64 crc_enc;
	int len = 0;

	buf = (char*)calloc(LICENSE_LENGTH_USER, sizeof(char));
	if (!buf)
		return -1;

	/* setup extra data */
	if (license_ops->lic_create) {
		len = license_ops->lic_create(buf, LICENSE_LENGTH_USER, data);
		if (len == -1)
			goto exit;
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

	len = LICENSE_LENGTH_USER - len;

	/* XoR encrypt crc */
	crc_enc = xor_encrypt_crc(buf, len);

	/* XoR encrypt user data */
	xor_user_data(buf, len);

	/* write crc to license file */
	if (swrite(&crc_enc, sizeof(u64), 1, ciphertext) != 1)
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
		char *file_name, char *buf, int *len)
{
	rsa_stream_t *ciphertext;
	struct rsa_stream_init init;
	char c;
	rsa_key_t *key = NULL;
	u1024_t seed;
	u64 crc;
	u64 crc_check;
	int ret = -1;

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

	/* assert crc is correct */
	crc = xor_decrypt_crc(crc);

	/* read user data from license */
	*len = sread(buf, sizeof(char), LICENSE_LENGTH_USER, ciphertext);
	/* assert there's no more to read in license */
	if (0 < sread(&c, sizeof(char), 1, ciphertext))
		goto exit;

	/* XoR decrypt user data */
	xor_user_data(buf, *len);

	/* take crc check */
	crc_check = rsa_crc(buf, *len);
	ret = crc == crc_check ? 0 : -1;

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
	char *buf;
	int len;
	int ret = -1;

	buf = (char*)calloc(LICENSE_LENGTH_USER, sizeof(char));
	if (!buf)
		return -1;

	if (rsa_license_get(pub_key_stream_init, file_name, buf, &len))
		goto exit;

	if (license_ops->lic_info)
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
	char *buf;
	int len;
	int ret = -1;

	buf = (char*)calloc(LICENSE_LENGTH_USER, sizeof(char));
	if (!buf)
		return -1;

	if (rsa_license_get(pub_key_stream_init, file_name, buf, &len))
		goto exit;

	if (license_ops->lic_extract)
		license_ops->lic_extract(buf, len, data);

	ret = 0;

exit:
	free(buf);
	return ret;
}

void rsa_license_init(void)
{
	rsa_encryption_level = 512;
}
