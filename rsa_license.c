#include <stdlib.h>
#include <stdio.h>
#include <sys/time.h>
#include <sys/stat.h>
#include "rsa_num.h"
#include "rsa_crc.h"
#include "rsa_license.h"

#define LICENSE_LENGTH_MAX 1024
#define LICENSE_LENGTH_USER (LICENSE_LENGTH_MAX - \
	(sizeof(u64) * (16 + 1) + sizeof(u64) * 2))

static void xor_user_data(char *buf, int len)
{
	int i;

	for (i = 0; i < len; i++)
		buf[i] ^= (char)RSA_RANDOM();
}

static void xor_encrypt_crc(u64 crc[2], char *buf, int len)
{
	crc[0] = rsa_crc(buf, len);
	crc[1] = crc[0] ^ (u64)RSA_RANDOM();
}

static int xor_decrypt_crc(u64 crc[2], u64 crc_check)
{
	/* assert correct public key is being used */
	crc[1] ^= (u64)RSA_RANDOM();
	if (crc[0] != crc[1])
		return -1;

	/* authenticate user data */
	if (crc[0] != crc_check)
		return -1;

	return 0;
}

/* 
 * License file format:
 *
 * +----------+----------------------------+--------------+
 * | Type     | Semantic                   | Encryption   |
 * +----------+----------------------------+--------------+
 * | u64      | random seed                | RSA          |
 * | u64      | random signature           | Plaintext    |
 * | u64      | random signature encrypted | Xor with RNG |
 * | ...      | user specific data...      | Xor with RNG |
 * +----------+----------------------------+--------------+
 */
int rsa_license_create(char *priv_key_path, char *file_name, 
		struct rsa_license_ops *license_ops, void *data)
{
	FILE *ciphertext;
	rsa_key_t *key = NULL;
	int ret = -1;
	char *buf;
	u64 crc[2];
	int len = 0;
	struct rsa_stream_init init;

	buf = calloc(LICENSE_LENGTH_USER, sizeof(char));
	if (!buf)
		return -1;

	/* setup extra data */
	if (license_ops->lic_create) {
		len = license_ops->lic_create(buf, LICENSE_LENGTH_USER, data);
		if (len == -1)
			goto exit;
	}

	/* open file */
	if (!(ciphertext = fopen(file_name, "w+")))
		goto exit;

	/* open private key */
	init.params.file.path = priv_key_path;
	init.params.file.mode = "r";
	init.type = RSA_STREAM_TYPE_FILE;
	key = rsa_key_open(&init, RSA_KEY_TYPE_PRIVATE, 1);
	if (!key)
		goto exit;

	/* RSA encrypt random seed */
	if (rsa_encrypt_seed(key, ciphertext))
		goto exit;

	len = LICENSE_LENGTH_USER - len;

	/* XoR encrypt user data */
	xor_user_data(buf, len);

	/* XoR encrypt crc */
	xor_encrypt_crc(crc, buf, len);

	/* write crc to license file */
	if (fwrite(crc, sizeof(u64), 2, ciphertext) != 2)
		goto exit;

	/* write user encrypted data to license file */
	if (fwrite(buf, sizeof(char), len, ciphertext) != len)
		goto exit;

	ret = 0;

exit:
	/* close file */
	if (ciphertext)
		fclose(ciphertext);

	/* close private key */
	rsa_key_close(key);

	/* on error remove file */
	if (ret)
		remove(file_name);

	/* cleanup buf */
	free(buf);

	return ret;
}

int rsa_license_get(char *pub_key_path, char *file_name, char *buf, int *len)
{
	FILE *ciphertext;
	char c;
	rsa_key_t *key = NULL;
	u1024_t seed;
	u64 crc[2];
	u64 crc_check;
	struct rsa_stream_init init;
	int ret = -1;

	/* open file */
	if (!(ciphertext = fopen(file_name, "r")))
		goto exit;

	/* open private key */
	init.params.file.path = pub_key_path;
	init.params.file.mode = "r";
	init.type = RSA_STREAM_TYPE_FILE;
	key = rsa_key_open(&init, RSA_KEY_TYPE_PUBLIC, 1);
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
	if (fread(crc, sizeof(u64), 2, ciphertext) != 2)
		goto exit;

	/* read user data from license */
	*len = fread(buf, sizeof(char), LICENSE_LENGTH_USER, ciphertext);
	/* assert there's no more to read in license */
	if (0 < fread(&c, sizeof(char), 1, ciphertext))
		goto exit;

	/* take crc check */
	crc_check = rsa_crc(buf, *len);

	/* XoR decrypt user data */
	xor_user_data(buf, *len);

	/* assert crc is correct */
	if (xor_decrypt_crc(crc, crc_check))
		goto exit;

	ret = 0;

exit:
	/* close file */
	if (ciphertext)
		fclose(ciphertext);

	/* close private key */
	rsa_key_close(key);

	return ret;
}

int rsa_license_info(char *pub_key_path, char *file_name,
		struct rsa_license_ops *license_ops)
{
	char *buf;
	int len;
	int ret = -1;

	buf = calloc(LICENSE_LENGTH_USER, sizeof(char));
	if (!buf)
		return -1;

	if (rsa_license_get(pub_key_path, file_name, buf, &len))
		goto exit;

	if (license_ops->lic_info)
		license_ops->lic_info(buf, len);

	ret = 0;

exit:
	free(buf);
	return ret;
}

int rsa_license_extract(char *pub_key_path, char *file_name,
		struct rsa_license_ops *license_ops, void *data)
{
	char *buf;
	int len;
	int ret = -1;

	buf = calloc(LICENSE_LENGTH_USER, sizeof(char));
	if (!buf)
		return -1;

	if (rsa_license_get(pub_key_path, file_name, buf, &len))
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

