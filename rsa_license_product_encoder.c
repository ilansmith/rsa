#include "rsa_license_product_encoder.h"

static char *v1[PRODUCT_VERSION_MAX_FEATURES] = { NULL };
static char *v2[PRODUCT_VERSION_MAX_FEATURES] = { "a", "b", "c" };
static char *v3[PRODUCT_VERSION_MAX_FEATURES] = { "A", "B", "C", "D" };
static char *v4[PRODUCT_VERSION_MAX_FEATURES] = { "AbX", "aBY", "me", "m" };

static char **features[] = { v1, v2, v3, v4 };

struct license_product rsa_license_product_encoder = {
	.name = "Encoder",
	.version = ARRAY_SIZE(features),
	.features = features,
};

