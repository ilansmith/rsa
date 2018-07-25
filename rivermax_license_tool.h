#ifndef _RIVERMAX_LICENSE_TOOL_H_
#define _RIVERMAX_LICENSE_TOOL_H_

#define FILE_FORMAT_VERSION 1
#define VENDOR_NAME_MAX_LENGTH 64

#define SECONDS_IN_HOUR (60 * 60)
#define SECONDS_IN_DAY (SECONDS_IN_HOUR * 24)
#define SECONDS_IN_MONTH (SECONDS_IN_DAY * 30)

#ifdef __cplusplus
extern "C" {
#endif

#include "rsa_num.h"

struct rsa_license_data {
	u64 version;
	char vendor_name[VENDOR_NAME_MAX_LENGTH];
	time_t time_limit;
};

#ifdef __cplusplus
}
#endif

#endif

