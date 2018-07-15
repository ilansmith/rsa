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

static int rsa_encrypt_format_version(char **buf, int *len, u64 version)
{
	if (*len < sizeof(u64))
		return -1;

	memcpy(*buf, &version, sizeof(u64));

	*buf += sizeof(u64);
	*len -= sizeof(u64);
	return 0;
}

static int rsa_encrypt_vendor_name(char **buf, int *len, char *vendor_name)
{
	int name_len;
	int i;

	name_len = strlen(vendor_name);
	if (*len < VENDOR_NAME_MAX_LENGTH || VENDOR_NAME_MAX_LENGTH <= name_len)
		return -1;

	for (i = 0; i < VENDOR_NAME_MAX_LENGTH; i++)
		(*buf)[i] = vendor_name[i];

	*buf += VENDOR_NAME_MAX_LENGTH;
	*len -= VENDOR_NAME_MAX_LENGTH;
	return 0;
}

static int rsa_encrypt_time_limit(char **buf, int *len, time_t time_limit)
{
	if (*len < sizeof(time_t))
		return -1;

	memcpy(*buf, &time_limit, sizeof(time_t));

	*buf += sizeof(time_t);
	*len -= sizeof(time_t);
	return 0;
}

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
static int rsa_license_create_rivermax(char *buf, int len, void *data)
{
	struct rsa_license_data *license_data = (struct rsa_license_data*)data;

	if (rsa_encrypt_format_version(&buf, &len, license_data->version)) {
		printf("failed to encrypt file format version: %llu\n",
			license_data->version);
		return -1;
	}

	if (rsa_encrypt_vendor_name(&buf, &len, license_data->vendor_name)) {
		printf("failed to encrypt vendor name: %s\n",
			license_data->vendor_name);
		return -1;
	}

	if (rsa_encrypt_time_limit(&buf, &len, license_data->time_limit)) {
		printf("failed to encrypt time limit: %lu\n",
			license_data->time_limit);
		return -1;
	}

	return len;
}

static int rsa_decrypt_version(char **buf, int *len)
{
	u64 version_enc;

	if (*len < sizeof(u64))
		return -1;

	version_enc = **((u64**)buf);
	printf("file format version: %llu\n", version_enc);

	*buf += sizeof(u64);
	*len -= sizeof(u64);
	return 0;
}

static int rsa_decrypt_vendor_name(char **buf, int *len)
{
	char vendor_name[VENDOR_NAME_MAX_LENGTH];
	int i;

	if (*len < VENDOR_NAME_MAX_LENGTH)
		return -1;

	for (i = 0; i < VENDOR_NAME_MAX_LENGTH; i++)
		vendor_name[i] = (*buf)[i];

	printf("vendor name: %s\n", vendor_name);

	*buf += VENDOR_NAME_MAX_LENGTH;
	*len -= VENDOR_NAME_MAX_LENGTH;
	return 0;
}

static int rsa_decrypt_time_limit(char **buf, int *len)
{
	time_t time_limit;
	char stime[50];

	if (*len < sizeof(time_t))
		return -1;

	time_limit = **(time_t**)buf;
	if (time_limit) {
		strftime(stime, sizeof(stime),"%d %b, %Y",
			localtime(&time_limit));
	} else {
		snprintf(stime, sizeof(stime), "unlimited");
	}
	printf("time limit: %s\n", stime);

	*buf += sizeof(time_t);
	*len -= sizeof(time_t);
	return 0;
}

static int rsa_license_parse_rivermax(char *buf, int len)
{
	if (rsa_decrypt_version(&buf, &len)) {
		printf("could not extract file format version\n");
		return -1;
	}

	if (rsa_decrypt_vendor_name(&buf, &len)) {
		printf("could not extract vendor name\n");
		return -1;
	}

	if (rsa_decrypt_time_limit(&buf, &len)) {
		printf("could not extract time limit\n");
		return -1;
	}

	return len;
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
	if (ret ) {
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

