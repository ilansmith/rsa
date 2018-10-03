#include "rsa_license_product_encrypter.h"

static char *v1[PRODUCT_VERSION_MAX_FEATURES] = { "hey", "he", "x" };

static char **features[] = { v1 };

struct license_product rsa_license_product_encrypter = {
	.name = "Encrypter",
	.version = ARRAY_SIZE(features),
	.features = features,
};

