# to build rsa unit tests compile with TESTS=y.
#
# - set u64 type definition by compiling with:
#   U64=UCHAR    for unsigned char
#   U64=USHORT   for unsigned short
#   U64=ULONG    for unsigned long
#   U64=ULLONG   for unsigned long long (default)
# 
# - to enable function timing feature compile with TIME_FUNCTIONS=y.
#
# - RSA encryption level can be set if U64 is set to ULLONG. This is done as
#   follows: 
#   ENC_LEVEL=64 (not yet implemented)
#   ENC_LEVEL=128
#   ENC_LEVEL=256
#   ENC_LEVEL=512
#   ENC_LEVEL=1024 (default)
#   for a non ULLONG value of U64 ENC_LEVEL=1024.
#
# normal compilation will produce rsa_enc (encrypter) and rsa_dec (decrypter).
# To compile a master utility (both encrypter and decrypter) compile with
# MASTER=y

CC=gcc
TARGET_OBJS=rsa_num.o rsa_util.o
CONFFILE=rsa.mk

-include $(CONFFILE)

CFLAGS=-Wall -Werror
LFLAGS=-lm

# Takuji Nishimura and Makoto Matsumoto's 64-bit version of Mersenne Twister 
# pseudorandom number generator
ifeq ($(MERSENNE_TWISTER),)
  MERSENNE_TWISTER=y
endif
ifeq ($(MERSENNE_TWISTER),y)
  TARGET_OBJS+=mt19937_64.o
  CFLAGS+=-DMERSENNE_TWISTER
endif

# set unit test configuration
ifeq ($(TESTS),y)

  TARGETS=rsa_test
  CFLAGS+=-DTESTS -g

  # enable/disable function timing
  ifeq ($(TIME_FUNCTIONS),y)
    CFLAGS+=-DTIME_FUNCTIONS
  endif
  ifeq ($(PROFILING),y)
    CFLAGS+=-pg
    LFLAGS+=-pg
  endif

  # u64 type definition
  U64_VALUES=UCHAR USHORT ULONG ULLONG
  ifeq ($(U64),)
    U64=ULLONG
  else
    ifeq ($(filter $(U64_VALUES),$(U64)),)
      $(error U64 possible values = {$(U64_VALUES)}) # error!
    endif
  endif

  CFLAGS+=-D$(U64)

  # set encryption level
  ifeq ($(U64),ULLONG)
    ENC_LEVEL_VALUES=128 256 512 1024 # 64:not yet implemented
    ifeq ($(ENC_LEVEL),)
      ENC_LEVEL=1024
    else
      ifeq ($(filter $(ENC_LEVEL_VALUES),$(ENC_LEVEL)),)
        $(error ENC_LEVEL possible values = {$(ENC_LEVEL_VALUES)}) # error!
      endif
    endif

    CFLAGS+=-DENC_LEVEL=$(ENC_LEVEL)
  endif

  TARGET_OBJS+=unit_test.o

else # create rsa applications
  ifeq ($(MASTER),y) # master encrypter/decrypter
    TARGETS=rsa
    CFLAGS+=-DRSA_MASTER
    TARGET_OBJS+=rsa_enc.o rsa_dec.o
  else # create separate encrypter/decrypter
    TARGETS=rsa_enc rsa_dec
    TARGET_OBJS+=rsa.o
  endif

  CFLAGS+=-DULLONG -g
endif

%.o: %.c
	$(CC) -o $@ $(CFLAGS) -c $<

.PHONY: all clean cleanapps cleantags cleanconf cleanall config

all: $(TARGETS)
rsa_test: $(TARGET_OBJS) rsa_test.o
	$(CC) -o $@ $(LFLAGS) $^
rsa: $(TARGET_OBJS) rsa.o
	$(CC) -o $@ $(LFLAGS) $^
rsa_enc: $(TARGET_OBJS) rsa_enc.o
	$(CC) -o $@ $(LFLAGS) $^
rsa_dec: $(TARGET_OBJS) rsa_dec.o
	$(CC) -o $@ $(LFLAGS) $^

config:
	@echo "doing make config"
	set -e; \
	rm -f $(CONFFILE); \
	echo "$(strip $(MAKEFLAGS))" | sed -e 's/ /\r\n/g' > $(CONFFILE);

clean:
	rm -f *.o gmon.out

cleanapps:
	file `ls` | grep executable | awk -F: '{ print $$1 }' | xargs rm -f

cleantags:
	rm -f tags

cleanconf:
	rm -f $(CONFFILE)

cleanall: clean cleanapps cleantags cleanconf
