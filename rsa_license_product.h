#ifndef _RSA_LICENSE_PRODUCT_H_
#define _RSA_LICENSE_PRODUCT_H_

#include <inttypes.h>
#include <stdlib.h>

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof(arr[0]))
#define BYTES2BITS(num) ((num) << 3)

#define PRODUCT_NAME_LEN_MAX 33
#define PRODUCT_VERSION_MAX_FEATURES (BYTES2BITS(sizeof(uint64_t)) - 1)

/*
 *          version            "1:ftr-1" NULL      NULL                NULL
 *           array              /         /         /                  /
 * o-----> +--------+    +-----/---+-----/---+-----/---+ ...... +-----/---+
 *         |        |    |    /    |    /    |    /    |        |    /    |
 *         | v1 o------->|   o     |   o     |   o     |        |   o     |
 *         |        |    |         |         |         |        |         |
 *         +--------+    +---------+---------+---------+ ...... +---------+
 *         |        |
 *         | v2 o-------> ...  "1:ftr-1" "2:ftr-2" NULL                NULL
 *         |        |           /         /         /                  /
 *         +--------+    +-----/---+-----/---+-----/---+ ...... +-----/---+
 *         |        |    |    /    |    /    |    /    |        |    /    |
 *         | v3 o------->|   o     |   o     |   o     |        |   o     |
 *         |        |    |         |         |         |        |         |
 *         +--------+    +---------+---------+---------+ ...... +---------+
 *         .        .
 *         .        .
 *         .        .
 *         .        .
 *         .        .          "1:ftr-1" "2:ftr-2" "3:ftr-3"        "63:ftr-63"
 *         .        .           /         /         /                  /
 *         +--------+    +-----/---+-----/---+-----/---+ ...... +-----/---+
 *         |        |    |    /    |    /    |    /    |        |    /    |
 *         | vN o------->|   o     |   o     |   o     |        |   o     |
 *         |        |    |         |         |         |        |         |
 *         +--------+    +---------+---------+---------+ ...... +---------+
 */
struct license_product {
	char *name; /* product name */
	int version; /* latest version (length of version array) */
	char ***features; /* pointer to version array */
};

char *license_product_name(struct license_product *product);
int license_product_name_len(struct license_product *product);
int license_product_version(struct license_product *product);
char **license_product_feature_list(struct license_product *product,
		int version);
int license_product_feature_num(struct license_product *product, int version);

struct license_product **license_products_get(void);
struct license_product *license_product_get_specific(char *name);
int license_list_products(char *specific);

#endif

