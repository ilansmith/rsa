# to build unit tests compile with DEBUG=y.
#
# - set u64 type definition by compiling with:
#   U64=UCHAR    for unsigned char (default)
#   U64=USHORT   for unsigned short
#   U64=ULONG    for unsigned long
#   U64=ULLONG   for unsigned long long
# 
# - to enable function timing feature compile with TIME_FUNCTIONS=y.
#   determine which functions are to be timed by assigning either ENABLED or 
#   DISSABLED in rsa_num.c:func_table[].

ALL_TARGETS=rsa unit_test
CFLAGS=-Wall -g
TARGET_OBJS=rsa_num.o
TARGET=rsa

ifeq ($(DEBUG),y)

TARGET=unit_test
TARGET_OBJS+=rsa_test.o
CFLAGS+=-DDEBUG

ifeq ($(TIME_FUNCTIONS),y)
CFLAGS+=-DTIME_FUNCTIONS
endif

ifeq ($(U64),UCHAR)
CFLAGS+=-DUCHAR
else
ifeq ($(U64),USHORT)
CFLAGS+=-DUSHORT
else
ifeq ($(U64),ULONG)
CFLAGS+=-DULONG
else
ifeq ($(U64),ULLONG)
CFLAGS+=-DULLONG
else
CFLAGS+=-DUCHAR
endif
endif
endif
endif
else #not debug
TARGET_OBJS+=main.o rsa_key.o rsa_file.o
endif

.PHONY: all clean cleanall
all: $(TARGET)

$(TARGET): $(TARGET_OBJS)
	gcc -o $@ $^

%.o: %.c
	gcc -o $@ $(CFLAGS) -c $<

rsa_test.o: rsa_test.c rsa.h
rsa_num.o: rsa_num.c rsa.h
main.o: main.c rsa.h
rsa_key.o: rsa_key.c rsa.h
rsa_file.o: rsa_file.c

clean:
	rm -rf *.o
cleanall: clean
	rm -rf $(ALL_TARGETS) tags
