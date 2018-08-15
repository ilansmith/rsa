#define _GUN_SOURCE

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#define SECONDS_IN_HOUR (60 * 60)
#define SECONDS_IN_DAY (SECONDS_IN_HOUR * 24)
#define SECONDS_IN_WEEK (SECONDS_IN_DAY * 7)
#define SECONDS_IN_MONTH (SECONDS_IN_DAY * 30)
#define SECONDS_IN_YEAR (SECONDS_IN_DAY * 365)

#define ROUND_UP(val, round) ((((val) + (round) - 1) / (round)) * (round))

static int days_in_month[12] = {
	31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31
};

static time_t round_up_end_of_day_localtime(time_t time_limit)
{
	time_t gmt_ts, eod_ts;
	struct tm time_info_gmt;
	time_t gmt_offset;

	if (!time_limit)
		return 0;

	gmtime_r(&time_limit, &time_info_gmt);
	time_info_gmt.tm_isdst = -1;
	gmt_ts = mktime(&time_info_gmt);
	if ((int)gmt_ts == -1)
		return (time_t)-1;

	gmt_offset = time_limit - gmt_ts;
	eod_ts = ROUND_UP(time_limit + gmt_offset, SECONDS_IN_DAY) -
		gmt_offset - 1;

	return eod_ts;
}

static int test_time_struct(time_t input)
{
	time_t round_up;
	time_t end;
	time_t end_round_up;
	char input_buf[100];
	char round_up_buf[100];
	char end_buf[100];
	char end_round_up_buf[100];
	char *endptr;

	round_up = round_up_end_of_day_localtime(input);

	ctime_r(&input, input_buf);
	ctime_r(&round_up, round_up_buf);
	printf("input (%lu) %sround up (%lu) %s\n", input, input_buf, round_up,
		round_up_buf);

	end = input + SECONDS_IN_DAY + 1 * SECONDS_IN_WEEK;
	end_round_up = round_up_end_of_day_localtime(end);
	ctime_r(&end, end_buf);
	ctime_r(&end_round_up, end_round_up_buf);
	printf("end (%lu) %send round up (%lu) %s\n", end, end_buf,
		end_round_up, end_round_up_buf);

	return 0;
}

static int test_time_string(char *date_str)
{
	unsigned short year;
	unsigned short month;
	unsigned short day;
	int is_leap_year;
	char buf[20];
	struct tm tm = { 0 };
	time_t t;
	int ret;

	if (strnlen(date_str, 9) != 8) {
		printf("date string too long: %s\n", date_str);
		return -1;
	}

	ret = sscanf(date_str, "%2hu%2hu%4hu", &day, &month, &year);
	if (ret != 3) {
		printf("succeeded to scan %d elements\n", ret);
		return -1;
	}

	is_leap_year = ((year & ~0<<2) == year) &&
		((year % 100) || !(year % 400));
	if (year < 1970) {
		printf("year is less than 1970: %hu\n", year);
		return -1;
	}
	if (month < 1 || 12 < month) {
		printf("month is not between 1 and 12: %hu\n", month);
		return -1;
	}
	if ((day < 1 || days_in_month[month - 1] < day) && (!is_leap_year ||
			month != 2 || day != days_in_month[1] + 1)) {
		printf("day is out of range: %hu\n", day);
		return -1;
	}

	printf("day:%hu, month:%hu, year:%hu\n", day, month, year);
	snprintf(buf, sizeof(buf), "%02u %02u %4u %s", day, month, year,
		"22 59 59");
	strptime(buf, "%d %m %Y %H %M %S", &tm);

	t = mktime(&tm);
	printf("is daylight saving: %s\n", tm.tm_isdst ? "yes" : "no");
	printf("buf: %s\n", buf);

	printf("\n");
	return test_time_struct(t);
}

int main(int argc, char **argv)
{
	char *optstring = "t:c:";
	char *endptr;
	time_t t;
	int ret;

	switch (getopt(argc, argv, optstring)) {
	case 't':
	t = strtol(optarg, &endptr, 10);
	if (*endptr) {
		printf("usage: ./a.out <time_t>\n");
		ret = -1;
	} else {
		ret = test_time_struct(t);
	}
	break;
	case 'c':
		ret = test_time_string(optarg);
		break;
	default:
		printf("usage: ./a.out <time_t>\n");
		ret = -1;
	}

	return ret;
}

