#include "rsa_util.h"

int code2code(code2code_t *list, int code)
{
    for (; list->code != -1 && list->code != code; list++);

    return list->code == -1 ? -1 : list->val;
}

char *code2str(code2str_t *list, int code)
{
    for (; list->code != -1 && list->code != code; list++);

    return list->code == -1 ? "" : list->str;
}

#if 0
int ias_pause(unsigned long sec, unsigned long microsec)
{
    struct timeval curr, end;

    if (gettimeofday(&end, NULL))
	return -1;
    end.tv_sec += sec;
    end.tv_usec += microsec;

    do
    {
	if (gettimeofday(&curr, NULL))
	    return -1;
    } while (curr.tv_sec <= end.tv_sec && curr.tv_usec <= end.tv_usec);

    return 0;
}
#endif
