#include "unit_test.h"
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <sys/select.h>

#define MIN(x, y) ((x) < (y) ? (x) : (y))
#define MAX_APP_NAME_SZ 256

#define UT_DISABLED(tests, t) ((tests)->is_disabled && \
    (tests)->is_disabled((t)->disabled))

/* io functionality */
int vscanf(const char *format, va_list ap);
static int first_comment;

int ask_user;

int vio_colour(vio_t vfunc, char *colour, char *fmt, va_list va)
{
    int ret;

    if (!colour)
	colour = C_NORMAL;

    ret = printf("%s", colour);
    ret += vfunc(fmt, va);
    ret += printf("%s", C_NORMAL);
    fflush(stdout);

    return ret;
}

int p_colour(char *colour, char *fmt, ...)
{
    int ret;
    va_list va;

    va_start(va, fmt);
    ret = vio_colour(vprintf, colour, fmt, va);
    va_end(va);

    return ret;
}

static int io_init(void)
{
    int ret = 0;

    if (first_comment)
    {
	ret = printf("\n");
	first_comment = 0;
    }

    return ret + p_colour(C_GREY, "> ");
}

static int _p_comment(char *fmt, va_list va, int is_newline)
{
    int ret = io_init();

    ret += vio_colour(vprintf, C_GREY, fmt, va);
    if (is_newline)
	ret += p_colour(C_NORMAL, "\n");

    return ret;
}

int p_comment(char *comment, ...)
{
    int ret;
    va_list va;

    va_start(va, comment);
    ret = _p_comment(comment, va, 0);
    va_end(va);

    return ret;
}

int p_comment_nl(char *comment, ...)
{
    int ret;
    va_list va;

    va_start(va, comment);
    ret = _p_comment(comment, va, 1);
    va_end(va);

    return ret;
}

static int to_vscanf(char *fmt, va_list va)
{
    fd_set fdr;
    struct timeval tv;
    int ret = 0, i, timeout = 10;

    for (i = 0; i < timeout; i++)
    {
	ret += vio_colour(vprintf, C_GREY, ".", NULL);

	tv.tv_sec = 0;
	tv.tv_usec = 500000;
	FD_ZERO(&fdr);
	FD_SET(0, &fdr);
	if (select(1, &fdr, NULL, NULL, &tv) || FD_ISSET(0, &fdr))
	    break;
    }

    return (i == timeout) ? 0 : ret + vio_colour(vscanf, C_GREY, fmt, va);
}

int s_comment(char *comment, char *fmt, ...)
{
    int ret, scn;
    va_list va;

    ret = io_init();
    va_start(va, fmt);
    ret += vio_colour(vprintf, C_GREY, comment, NULL);
    ret += (scn = to_vscanf(fmt, va)) ? scn : printf("\n");
    va_end(va);

    return ret;
}

static void p_test_summery(int total, int passed, int failed, int known_issues, 
    int disabled, char *summery_comment)
{
    printf("\ntest summery%s%s%s\n", summery_comment ? " (" : "", 
	summery_comment ? summery_comment : "", summery_comment ? ")" : "");
    printf("------------\n");
    printf("%stotal:        %i%s\n", C_HIGHLIGHT, total, C_NORMAL);
    printf("passed:       %i\n", passed);
    printf("failed:       %i\n", failed);
    printf("known issues: %i\n", known_issues);
    printf("disabled:     %i\n", disabled);
}

static char *app_name(char *argv0)
{
    char *name, *ptr;
    static char path[MAX_APP_NAME_SZ];

    snprintf(path, MAX_APP_NAME_SZ, argv0);
    for (name = ptr = path; *ptr; ptr++)
    {
	if (*ptr != '/')
	    continue;

	name = ptr + 1;
    }
    return name;
}

static void test_usage(char *path)
{
    char *app = app_name(path);

    printf("usage:\n"
	"%s               - run all tests\n"
	"  or\n"
	"%s <test>        - run a specific test\n"
	"  or\n"
	"%s <from> <to>   - run a range of tests\n"
	"  or\n"
	"%s list          - list all tests\n",
	app, app, app, app);
}

static int test_getarg(char *arg, int *arg_ival, int min, int max)
{
    char *err;

    *arg_ival = strtol(arg, &err, 10);
    if (*err)
	return -1;
    if (*arg_ival < min || *arg_ival > max)
    {
	printf("test number out of range: %i\n", *arg_ival);
	return -1;
    }
    return 0;
}

static int test_getargs(int argc, char *argv[], int *from, int *to, int max)
{
    if (argc > 3)
    {
	test_usage(argv[0]);
	return -1;
    }

    if (argc == 1)
    {
	*from = 0;
	*to = max;
	ask_user = 1;
	return 0;
    }

    /* 2 <= argc <= 3*/
    if (test_getarg(argv[1], from, 1, max))
    {
	test_usage(argv[0]);
	return -1;
    }

    if (argc == 2)
    {
	*to = *from;
    }
    else /* argc == 3 */
    {
	if (test_getarg(argv[2], to, *from, max))
	{
	    test_usage(argv[0]);
	    return -1;
	}
    }

    (*from)--; /* map test number to table index */
    return 0;
}

static int is_list_tests(int argc, char *argv[], unit_test_t *tests)
{
    int i, size = tests->size;
    char *list_comment = tests->list_comment;
    test_t *arr = tests->arr;

    if (argc != 2 || strcmp(argv[1], "list"))
	return 0;

    p_colour(C_HIGHLIGHT, "%s unit tests%s%s%s\n", app_name(argv[0]), 
	list_comment ? " (" : "", list_comment ? list_comment : "", 
	list_comment ? ")" : "");
    for (i = 0; i < size - 1; i++)
    {
	test_t *t =  &arr[i];
	int is_disabled = UT_DISABLED(tests, t);

	printf("%i. ", i + 1);
	p_colour(is_disabled ? C_GREY : C_NORMAL, "%s", 
	    t->description);
	if (is_disabled)
	    p_colour(C_CYAN, " (disabled)");
	else if (t->known_issue)
	{
	    p_colour(C_BLUE, " (known issue: ");
	    p_colour(C_GREY, t->known_issue);
	    p_colour(C_BLUE, ")");
	}
	printf("\n");
    }

    return 1;
}

int unit_test(int argc, char *argv[], unit_test_t *tests)
{
    test_t *t;
    int from, to, max = tests->size, ret;
    int  total = 0, disabled = 0, passed = 0, failed = 0, known_issues = 0;

    if (tests->tests_init)
	tests->tests_init(argc, argv);

    if (is_list_tests(argc, argv, tests))
	return 0;

    if (test_getargs(argc, argv, &from, &to, max - 1))
	return -1;

    for (t = &tests->arr[from]; t < tests->arr + MIN(to, max); t++)
    {
	first_comment = 1;
	total++;
	printf("%i. %s: ", from + total, t->description);
	if (UT_DISABLED(tests, t))
	{
	    disabled++;
	    p_colour(C_CYAN, "disabled\n");
	    continue;
	}
	if (t->known_issue)
	{
	    p_colour(C_BLUE, "known issue: ");
	    p_colour(C_NORMAL, "%s\n", t->known_issue);
	    known_issues++;
	    continue;
	}
	if (!t->func)
	{
	    p_colour(C_CYAN, "function does not exist\n");
	    return -1;
	}
	fflush(stdout);

	if (tests->pre_test)
	    tests->pre_test();

	if ((ret = t->func()))
	{
	    p_colour(C_RED, "Failed");
	    failed++;
	}
	else
	{
	    p_colour(C_GREEN, "OK");
	    passed++;
	}
	printf("\n");
    }

    p_test_summery(total, passed, failed, known_issues, disabled, 
	tests->summery_comment);
    return 0;
}

