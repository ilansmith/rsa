#include <time.h>
#include "rsa_license.h"

#define FILE_FORMAT_VERSION 1
#define VENDOR_NAME_MAX_LENGTH 64
#define ROUND_UP(val, multiple) ((((val) + (multiple) - 1) / (multiple)) * \
		(multiple))

struct rsa_license_data {
	u64 version;
	char vendor_name[VENDOR_NAME_MAX_LENGTH];
	time_t time_limit;
};

/* 
 * Specific license file format:
 *
 * +----------+----------------------------+--------------+
 * | Type     | Semantic                   | Encryption   |
 * +----------+----------------------------+--------------+
 * | u64      | file format version        | XoR with RNG |
 * | char[64] | vendor name                | XoR with RNG |
 * | time_t   | time limit                 | Xor with RNG |
 * +----------+----------------------------+--------------+
 */

static int rsa_encrypt_format_version(FILE *ciphertext, u64 version)
{
	int written;
	u64 version_enc;

	version_enc = version ^ RSA_RANDOM();

	written = fwrite(&version_enc, sizeof(u64), 1, ciphertext);
	return written == 1 ? 0 : -1;
}

static int rsa_encrypt_vendor_name(FILE *ciphertext, char *vendor_name)
{
	int written;
	char vendor_name_enc[VENDOR_NAME_MAX_LENGTH];
	int len;
	int i;

	len = strlen(vendor_name_enc);
	if (len >= VENDOR_NAME_MAX_LENGTH)
		return -1;

	for (i = 0; i <VENDOR_NAME_MAX_LENGTH; i++)
		vendor_name_enc[i] = (char)(vendor_name[i] ^ RSA_RANDOM());

	written = fwrite(&vendor_name_enc, sizeof(char), VENDOR_NAME_MAX_LENGTH,
		ciphertext);
	return written == VENDOR_NAME_MAX_LENGTH ? 0 : -1;
}

static int rsa_encrypt_time_limit(FILE *ciphertext, time_t time_limit)
{
	int written;
	time_t time_limit_enc;

	time_limit_enc = (time_t)(time_limit ^ RSA_RANDOM());

	written = fwrite(&time_limit_enc, sizeof(time_t), 1, ciphertext);
	return written == 1 ? 0 : -1;
}

static int rsa_license_create_rivermax(FILE *ciphertext, void *data)
{
	struct rsa_license_data *license_data =
		(struct rsa_license_data*)data;

	if (rsa_encrypt_format_version(ciphertext, license_data->version)) {
		printf("failed to encrypt file format version: %llu\n",
			license_data->version);
		return -1;
	}

	if (rsa_encrypt_vendor_name(ciphertext, license_data->vendor_name)) {
		printf("failed to encrypt vendor name: %s\n",
			license_data->vendor_name);
		return -1;
	}

	if (rsa_encrypt_time_limit(ciphertext, license_data->time_limit)) {
		printf("failed to encrypt time limit: %lu\n",
			license_data->time_limit);
		return -1;
	}
	return 0;
}

static int rsa_decrypt_version(FILE *ciphertext)
{
	int read;
	u64 version_enc;

	read = fread(&version_enc, sizeof(u64), 1, ciphertext);
	if (read != 1)
		return -1;

	printf("file format version: %llu\n", version_enc ^ RSA_RANDOM());
	return 0;
}

static int rsa_decrypt_vendor_name(FILE *ciphertext)
{
	int read;
	char vendor_name[VENDOR_NAME_MAX_LENGTH];
	int i;

	read = fread(&vendor_name, sizeof(char), VENDOR_NAME_MAX_LENGTH,
		ciphertext);
	if (read != VENDOR_NAME_MAX_LENGTH)
		return -1;

	for (i = 0; i < VENDOR_NAME_MAX_LENGTH; i++)
		vendor_name[i] = vendor_name[i] ^ RSA_RANDOM();

	printf("vendor name: %s\n", vendor_name);
	return 0;
}

static int rsa_decrypt_time_limit(FILE *ciphertext)
{
	int read;
	time_t time_limit_enc;
	time_t time_limit;
	char stime[50];

	read = fread(&time_limit_enc, sizeof(time_t), 1, ciphertext);
	if (read != 1)
		return -1;

	time_limit = (time_t)(time_limit_enc ^ RSA_RANDOM());
	if (time_limit) {
		strftime(stime, sizeof(stime),"%d %b, %Y",
			localtime(&time_limit));
	} else {
		snprintf(stime, sizeof(stime), "unlimited");
	}
	printf("time limit: %s\n", stime);
	return 0;
}

static int rsa_license_parse_rivermax(FILE *ciphertext)
{
	if (rsa_decrypt_version(ciphertext)) {
		printf("could not extract file format version\n");
		return -1;
	}

	if (rsa_decrypt_vendor_name(ciphertext)) {
		printf("could not extract vendor name\n");
		return -1;
	}

	if (rsa_decrypt_time_limit(ciphertext)) {
		printf("could not extract time limit\n");
		return -1;
	}
	return 0;
}

static time_t get_time_limit(int do_limit)
{
	time_t t = 0;
	char stime[50];

	t = time(NULL);
	strftime(stime, sizeof(stime),"%d %b, %Y", localtime(&t));
	printf("current time: %s\n", stime);

	if (do_limit) {
		int seconds_in_day = 60*60*24;

		t = ROUND_UP(t + seconds_in_day * 30, seconds_in_day);
		strftime(stime, sizeof(stime),"%d %b, %Y", localtime(&t));
	} else {
		t = 0;
		snprintf(stime, sizeof(stime), "unlimited");
	}

	printf("setting time limit to: %s\n", stime);

	return t;
}

int main(int argc, char **argv)
{
	struct rsa_license_ops licnese_ops = {
		rsa_license_create_rivermax,
		rsa_license_parse_rivermax,
		NULL
	};
	struct rsa_license_data license_data;
	char *public_key = "/home/ilan/.rsa/rivermax.pub";
	char *private_key = "/home/ilan/.rsa/rivermax.prv";
	char *license = "rivermax.lic";
	int ret;

	license_data.version = 1;
	snprintf(license_data.vendor_name, VENDOR_NAME_MAX_LENGTH,
		"GrassValley");
	license_data.time_limit = get_time_limit(1);

	rsa_license_init();

	ret = rsa_license_create(private_key, license, &licnese_ops,
		&license_data);
	if (ret) {
		printf("rsa_license_create() failed\n");
		return -1;
	}

	printf("\n");

	ret = rsa_license_info(public_key, license, &licnese_ops);
	if (ret) {
		printf("rsa_license_info() failed\n");
		return -1;
	}

	return 0;
}

