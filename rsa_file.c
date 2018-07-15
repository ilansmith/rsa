#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#define FILENAME_PREFFIX_LEN 255
#define COUNTER_MAX_LEN 3
#define FILENAME_SUFFIX ".rsa"
#define FILENAME_SUFFIX_LEN 4

typedef int (* stat_func_t) (const char *fname, struct stat *buf);

static char *rsa_file_name(char *preffix, stat_func_t stat_f, int is_new)
{
    static char name_buf[FILENAME_PREFFIX_LEN + FILENAME_SUFFIX_LEN + 1]; 
    char name_counter[COUNTER_MAX_LEN], *counter_ptr = name_buf + 
	strlen(preffix) + 1;
    int i = 1, file_exists;
    struct stat buf;

    if (strlen(preffix) > FILENAME_PREFFIX_LEN)
	return NULL;
    strncpy(name_buf, preffix, FILENAME_PREFFIX_LEN);
    strcat(name_buf, FILENAME_SUFFIX);

    while ((file_exists = !stat_f(name_buf, &buf)) && is_new)
    {
	if (snprintf(name_counter, COUNTER_MAX_LEN, "_%i", i++) >= 
	    COUNTER_MAX_LEN)
	{
	    return NULL;
	}
	*counter_ptr = 0;
	strcat(name_buf, name_counter);
	strcat(name_buf, FILENAME_SUFFIX);
    }

    return (file_exists && !is_new) || (!file_exists && is_new) ? name_buf : 
	NULL;
}

FILE *rsa_file_open(char *preffix, int is_slink, int is_new)
{
    char *fname = NULL;

    if (!(fname = rsa_file_name(preffix, is_slink ? lstat : stat, is_new)))
	return NULL;

    return fopen(fname, is_new ? "w+" : "r+");
}

int rsa_file_close(FILE *fp)
{
    return fclose(fp);
}

