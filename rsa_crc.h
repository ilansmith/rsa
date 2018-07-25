#ifndef _RSA_CRC_H_
#define _RSA_CRC_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "rsa_num.h"

u64 rsa_crc(char *str, size_t len);

#ifdef __cplusplus
}
#endif

#endif

