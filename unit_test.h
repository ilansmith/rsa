#ifndef _UNIT_TEST_H_
#define _UNIT_TEST_H_

#include <stdio.h>
#include <stdarg.h>

/* unit_test.h should be included after the tested code's header files so that 
 * if it defines any of the following definitions it should get  presedence */

#ifndef C_CYAN
#define C_CYAN "\033[01;36m"
#endif
#ifndef C_RED
#define C_RED "\033[01;31m"
#endif
#ifndef C_GREEN
#define C_GREEN "\033[01;32m"
#endif
#ifndef C_BLUE
#define C_BLUE "\033[01;34m"
#endif
#ifndef C_GREY
#define C_GREY "\033[00;37m"
#endif
#ifndef C_NORMAL
#define C_NORMAL "\033[00;00;00m"
#endif
#ifndef C_HIGHLIGHT
#define C_HIGHLIGHT "\033[01m"
#endif
#ifndef CURSOR_POS_SAVE
#define CURSOR_POS_SAVE "\033[s"
#endif
#ifndef CURSOR_POS_RESTORE
#define CURSOR_POS_RESTORE "\033[u"
#endif
#ifndef CURSOR_MOV_UP
#define CURSOR_MOV_UP "\033[%dA"
#endif
#ifndef CURSOR_MOV_DOWN
#define CURSOR_MOV_DOWN "\033[%dB"
#endif

#ifndef ARRAY_SZ
#define ARRAY_SZ(arr) (sizeof(arr) / sizeof(arr[0]))
#endif 

typedef struct {
    char *description;
    char *known_issue;
    int (* func)(void);
    int disabled;
} test_t;

typedef struct {
    test_t *arr;
    int size;
    char *list_comment;
    char *summery_comment;
    void (*tests_init)(int argc, char *argv[]);
    int (*is_disabled)(int flags);
    void (*pre_test)(void);
} unit_test_t;

typedef int (*vio_t)(const char *format, va_list ap);
int vio_colour(vio_t vfunc, char *colour, char *fmt, va_list va);
int p_colour(char *colour, char *fmt, ...);
int io_init(void);
int p_comment(char *comment, ...);
int s_comment(char *comment, char *fmt, ...);
int unit_test(int argc, char *argv[], unit_test_t *tests);
extern int ask_user;

#endif
