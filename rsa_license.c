#include <stdlib.h>
#include <stdio.h>
#include <sys/time.h>
#include <sys/stat.h>
#include "rsa_num.h"
#include "rsa_license.h"

static int rsa_encrypt_signature(FILE *ciphertext)
{
	int written;
	u64 signature;
	u64 signature_enc;

	signature = RSA_RANDOM();
	signature_enc = signature ^ RSA_RANDOM();

	written = fwrite(&signature, sizeof(u64), 1, ciphertext);
	if (written != 1)
		return -1;
	written = fwrite(&signature_enc, sizeof(u64), 1, ciphertext);
	if (written != 1)
		return -1;

	return 0;
}

static int rsa_decrypt_signature(FILE *ciphertext)
{
	int read;
	u64 signature_expected;
	u64 signature;
	u64 signature_enc;

	signature_expected = RSA_RANDOM();

	read = fread(&signature, sizeof(u64), 1, ciphertext);
	if (read != 1)
		return -1;

	if (signature != signature_expected)
		return -1;

	read = fread(&signature_enc, sizeof(u64), 1, ciphertext);
	if (read != 1)
		return -1;

	return signature == (signature_enc ^ RSA_RANDOM()) ? 0 : -1;
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
 * | ...      | specific data...           | Xor with RNG |
 * +----------+----------------------------+--------------+
 */
int rsa_license_create(char *priv_key_path, char *file_name, 
		struct rsa_license_ops *license_ops, void *data)
{
	FILE *ciphertext;
	rsa_key_t *key = NULL;
	int ret = -1;

	/* open file */
	if (!(ciphertext = fopen(file_name, "w+")))
		goto exit;

	/* open private key */
	key = rsa_key_open(priv_key_path, RSA_KEY_TYPE_PRIVATE, 1);
	if (!key)
		goto exit;

	/* RSA encrypt random seed */
	if (rsa_encrypt_seed(key, ciphertext))
		goto exit;

	/* Generate and XoR encrypt a signature */
	if (rsa_encrypt_signature(ciphertext))
		goto exit;

	/* encrypte extra data */
	if (license_ops->lic_create &&
			license_ops->lic_create(ciphertext, data)) {
		goto exit;
	}

	ret = 0;

exit:
	/* close private key */
	rsa_key_close(key);

	/* close file */
	if (ciphertext)
		fclose(ciphertext);

	/* on error remove file */
	if (ret)
		remove(file_name);

	return ret;
}

int rsa_license_info(char *pub_key_path, char *file_name,
		struct rsa_license_ops *license_ops)
{
	FILE *ciphertext;
	rsa_key_t *key = NULL;
	u1024_t seed;
	int ret = -1;

	/* open file */
	if (!(ciphertext = fopen(file_name, "r")))
		goto exit;

	/* open private key */
	key = rsa_key_open(pub_key_path, RSA_KEY_TYPE_PUBLIC, 1);
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

	/* read signature */
	if (rsa_decrypt_signature(ciphertext))
		goto exit;

	if (license_ops->lic_parse && license_ops->lic_parse(ciphertext))
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

void rsa_license_init(void)
{
	rsa_encryption_level = 512;
}

