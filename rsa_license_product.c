#include <stdio.h>
#include <string.h>
#include "rsa_license_product.h"

#include "rsa_license_product_encoder.h"
#include "rsa_license_product_encrypter.h"

char *license_product_name(struct license_product *product)
{
	return product->name;
}

int license_product_name_len(struct license_product *product)
{
	return (int)strnlen(product->name, PRODUCT_NAME_LEN_MAX);
}

int license_product_version(struct license_product *product)
{
	return product->version;
}

char **license_product_feature_list(struct license_product *product,
		int version)
{
	if (product->version < version)
		return NULL;

	return product->features[version - 1];
}

int license_product_feature_num(struct license_product *product, int version)
{
	char **features;
	int ret;

	features = license_product_feature_list(product, version);
	if (!features)
		return -1;

	for (ret = 0; ret < (int)PRODUCT_VERSION_MAX_FEATURES && features[ret];
		ret++);
	return ret;
}

struct license_product **license_products_get(void)
{
	static struct license_product *products[] = {
		&rsa_license_product_encoder,
		&rsa_license_product_encrypter,
		NULL,
	};

	return (struct license_product**)products;
}

struct license_product *license_product_get_specific(char *name)
{
	struct license_product **product = license_products_get();
	struct license_product *found = NULL;
	int name_len = (int)strnlen(name, PRODUCT_NAME_LEN_MAX);

	for (product = license_products_get(); *product; product++) {
		int is_match;

		if (strncasecmp((*product)->name, name, name_len))
			continue;

		is_match = strlen((*product)->name) == (size_t)name_len;
		if (found && !is_match) {
			printf("Ambiguous prefix: %s (%s, %s)\n", name,
				found->name, (*product)->name);

			return NULL;
		}

		found = *product;
		if (is_match)
			break;
	}

	if (!found)
		printf("Unsupported product: %s\n", name);

	return found;
}

static void list_products_features(struct license_product *product)
{
	int v;
	int version = license_product_version(product);

	printf("%s\n", license_product_name(product));
	for (v = 1; v <= version; v++) {
		char **features = license_product_feature_list(product, v);
		int f;

		printf("  v%d: ", v);
		for (f = 0; f < (int)PRODUCT_VERSION_MAX_FEATURES &&
				features[f]; f++) {
			printf("%s%s", f ? ", " : "", features[f]);
		}

		if (!f)
			printf("full features");

		printf("\n");
	}
}

int license_list_products(char *specific)
{
	struct license_product **products;
	struct license_product *found = NULL;
	size_t specific_len = 0;

	if (specific && *specific)
		specific_len = strnlen(specific, PRODUCT_NAME_LEN_MAX);

	for (products = license_products_get(); *products; products++) {
		int is_match;

		if (!specific || !*specific) {
			printf("%s\n", license_product_name(*products));
			continue;
		}

		if (strncasecmp(license_product_name(*products), specific,
				specific_len)) {
			continue;
		}

		is_match =
			strlen(license_product_name(*products)) == specific_len;

		if (found && !is_match) {
			printf("Ambiguous prefix: %s (%s, %s)\n", specific,
				found->name, (*products)->name);
			return -1;
		}

		found = *products;
		if (is_match)
			break;
	}

	if (!specific || !*specific)
		return 0;

	if (!found) {
		printf("Product %s not found\n", specific);
		return -1;
	}

	list_products_features(found);
	return 0;
}

