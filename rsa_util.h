#ifndef _UTIL_H_
#define _UTIL_H_

#if 0
#include <stdlib.h>
#include <sys/time.h>
#include <time.h>
#endif

#define ARRAY_SZ(arr) (sizeof(arr) / sizeof(arr[0]))

typedef struct code2code_t {
    int code;
    int val;
    int disabled;
} code2code_t;

typedef struct code2str_t {
    int code;
    char *str;
    int disabled;
} code2str_t;

int code2code(code2code_t *list, int code);
char *code2str(code2str_t *list, int code);

#if 0
/* busy wait for sec seconds and microsec seconds */
int ias_pause(unsigned long sec, unsigned long microsec);
#endif
#endif

