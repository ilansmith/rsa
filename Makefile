# to build rsa unit tests compile with CONFIG_TESTS=y.
#
# - set u64 type definition by compiling with:
#   U64=UCHAR    for unsigned char
#   U64=USHORT   for unsigned short
#   U64=UINT     for unsigned long
#   U64=ULLONG   for unsigned long long (default)
# 
# - to enable function timing feature compile with CONFIG_TIME_FUNCTIONS=y.
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
# CONFIG_MASTER=y

CC=gcc
AR=ar
CONFFILE=rsa.mk
LIB_RSA=librsa.a
LIB_RSA_OBJS=rsa_num.o rsa_util.o rsa_stream.o
LIB_RSA_LIC=librsalic.a
LIB_RSA_LIC_OBJS=rsa_crc.o rsa_license.o 
TARGET_RSA_TEST=rsa_test
TARGET_RSA=rsa
TARGET_RSA_ENC=rsa_enc
TARGET_RSA_DEC=rsa_dec
TARGET_RSA_LICENSE=license
CYGWIN_COMPAT=echo "$1" | sed -e 's/--\|$(MAKE_MODE)//g'

-include $(CONFFILE)

CFLAGS=-Wall -Werror -Wno-unused-result
LFLAGS=-L. -lm -l$(patsubst lib%.a,%,$(LIB_RSA))

# Takuji Nishimura and Makoto Matsumoto's 64-bit version of Mersenne Twister 
# pseudo random number generator
ifeq ($(CONFIG_MERSENNE_TWISTER),)
  CONFIG_MERSENNE_TWISTER=y
endif
ifeq ($(CONFIG_MERSENNE_TWISTER),y)
  LIB_RSA_OBJS+=mt19937_64.o
  CFLAGS+=-DCONFIG_MERSENNE_TWISTER
endif

# enable/disable output colouring (enabled by default)
ifeq ($(CONFIG_RSA_COLOURS),)
  CONFIG_RSA_COLOURS=y
endif
ifeq ($(CONFIG_RSA_COLOURS),y)
  CFLAGS+=-DCONFIG_RSA_COLOURS
endif

# set unit test configuration
ifeq ($(CONFIG_TESTS),y)

  TARGETS=$(TARGET_RSA_TEST)
  CFLAGS+=-DCONFIG_TESTS

  # enable/disable function timing
  ifeq ($(CONFIG_TIME_FUNCTIONS),y)
    CFLAGS+=-DCONFIG_TIME_FUNCTIONS
  endif
  ifeq ($(CONFIG_PROFILING),y)
    CFLAGS+=-pg
    LFLAGS+=-pg
  endif

  # u64 type definition
  U64_VALUES=UCHAR USHORT UINT ULLONG
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

  # enable/disable debug mode (disabled by default)
  ifeq ($(CONFIG_DEBUG),y)
    CFLAGS+=-O0 -g
  else
    CFLAGS+=-O3
  endif

  TARGET_OBJS_rsa_test+=unit_test.o rsa_test.o

else # create rsa applications
  TARGET_OBJS_rsa=rsa.o
  TARGET_OBJS_rsa_enc=rsa_enc.o 
  TARGET_OBJS_rsa_dec=rsa_dec.o 
  ifeq ($(CONFIG_MASTER),y) # master encrypter/decrypter
    TARGETS=$(TARGET_RSA) $(TARGET_RSA_LICENSE)
    CFLAGS+=-DRSA_MASTER
    TARGET_OBJS_rsa+=$(TARGET_OBJS_rsa_enc) $(TARGET_OBJS_rsa_dec) rsa_main.o
  else # create separate encrypter/decrypter
    TARGETS=$(TARGET_RSA_ENC) $(TARGET_RSA_DEC) $(TARGET_RSA_LICENSE)
    TARGET_OBJS_rsa_enc+=rsa_enc_main.o
    TARGET_OBJS_rsa_dec+=rsa_dec_main.o
  endif

  TARGET_OBJS_rsa_license=rsa_license_main.o
  CFLAGS+=-DULLONG -O0 -g
endif

%.o: %.c
	$(CC) -o $@ $(CFLAGS) -c $<

.PHONY: all clean cleanapps cleantags cleanconf cleanall config

all: $(TARGETS)
$(TARGET_RSA_TEST): $(LIB_RSA) $(TARGET_OBJS_rsa_test)
	$(CC) -o $@ $^ $(LFLAGS)
$(TARGET_RSA): $(LIB_RSA) $(TARGET_OBJS_rsa)
	$(CC) -o $@ $^ $(LFLAGS)
$(TARGET_RSA_ENC): $(LIB_RSA) $(TARGET_OBJS_rsa) $(TARGET_OBJS_rsa_enc)
	$(CC) -o $@ $^ $(LFLAGS)
$(TARGET_RSA_DEC): $(LIB_RSA) $(TARGET_OBJS_rsa) $(TARGET_OBJS_rsa_dec)
	$(CC) -o $@ $^ $(LFLAGS)
$(TARGET_RSA_LICENSE): $(LIB_RSA_LIC) $(TARGET_OBJS_rsa_license)
	$(CC) -o $@  $(TARGET_OBJS_rsa_license) $(LFLAGS)

$(LIB_RSA): $(LIB_RSA_OBJS)
	$(AR) -r $@ $^

$(LIB_RSA_LIC): $(LIB_RSA) $(LIB_RSA_LIC_OBJS)
	$(AR) -r $< $^

config:
	@echo "doing make config"
	set -e; \
	rm -f $(CONFFILE); \
	echo $$($(strip $(call CYGWIN_COMPAT, $(MAKEFLAGS)))) | \
	sed -e 's/ /\r\n/g' > $(CONFFILE);

clean:
	rm -f *.o *.a gmon.out

cleanapps:
	rm -f $(TARGET_RSA_TEST) $(TARGET_RSA) $(TARGET_RSA_ENC) $(TARGET_RSA_DEC) $(TARGET_RSA_LICENSE)

cleantags:
	rm -f tags

cleanconf:
	rm -f $(CONFFILE)

cleanall: clean cleanapps cleantags cleanconf

define hl
\033[1m$1\033[0m
endef

define help_print_tool
  @printf "$(call hl,%-23s) - %s.\n" $1 $2
endef

help:
	@printf "usage:\n"
	@printf "     $$ $(call hl,make [OPTIONS])\n"
	@printf "       or\n"
	@printf "     $$ $(call hl,make config [OPTIONS])\n"
	@printf "     $$ $(call hl,make)\n"
	@printf "       or\n"
	@printf "     $$ $(call hl,make clean)      [clean object files]\n"
	@printf "     $$ $(call hl,make cleanapps)  [clean executables]\n"
	@printf "     $$ $(call hl,make cleanconf)  [clean make configuration file]\n"
	@printf "     $$ $(call hl,make cleantags)  [clean tag file]\n"
	@printf "     $$ $(call hl,make cleanall)   [clean all]\n"
	@printf "\n"
	@printf "By issuing $(call hl, make config) it is possible to recompile by simply issuing $(call hl,make),\n"
	@printf "without the need to repeat the entire build command line.\n"
	@printf "\n"
	@printf "If no '$(call hl,OPTIONS)' are provided then $(call hl,$(TARGET_RSA_ENC)) and $(call hl,$(TARGET_RSA_DEC)) are built.\n"
	@printf "If $(call hl,CONFIG_MASTER=y), then a master utility is built (enc/dec combined in one).\n"
	@printf "In both cases $(call hl,$(TARGET_RSA_LICENSE)) is also built.\n"
	@printf "\n"
	@printf "Set $(call hl,CONFIG_MERSENNE_TWISTER=y) (default) to use Takuji Nishimura and Makoto\n"
	@printf "Matsumoto's 64-bit version Mersenne Twister PRNG (Pseudorandom Number Generator).\n"
	@printf "If $(call hl,CONFIG_MERSENNE_TWISTER=n) then random(3) is used as a PRNG instead.\n"
	@printf "\n"
	@printf "If $(call hl,CONFIG_TESTS=y), then $(call hl,$(TARGET_RSA_TEST)) is built (rsa unit tests). In this case:\n"
	$(call help_print_tool,"U64=UCHAR","define u64 as unsigned char")
	$(call help_print_tool,"U64=USHORT","define u64 as unsigned short")
	$(call help_print_tool,"U64=UINT","define u64 as unsigned int")
	$(call help_print_tool,"U64=ULLONG","define u64 as unsigned long long (default)")
	@printf "\n"
	@printf "In the case of $(call hl,U64=ULLONG), the following options are available as well:\n"
	$(call help_print_tool,"ENC_LEVEL=64","not yet implemented")
	$(call help_print_tool,"ENC_LEVEL=128","tests encryption level: 128")
	$(call help_print_tool,"ENC_LEVEL=256","tests encryption level: 256")
	$(call help_print_tool,"ENC_LEVEL=512","tests encryption level: 512")
	$(call help_print_tool,"ENC_LEVEL=1024","tests encryption level: 1024 (default)")
	@printf "\n"
	@printf "Note that different sets of unit tests are enabled for different values of $(call hl,U64).\n"
	@printf "\n"
	$(call help_print_tool,"CONFIG_TIME_FUNCTIONS=y","time functions for profiling)"
	$(call help_print_tool,"CONFIG_PROFILING=y","build unit tests for profling with gprof(1)")
	$(call help_print_tool,"CONFIG_DEBUG=y","build without optimizations and generate debug symbols")
	@printf "\n"
	@printf "Enhanced colour output is enabled by default or explicitly if\n"
	@printf "$(call hl,CONFIG_RSA_COLOURS=y) is set.\n"
	@printf "To build without enhanced colour output use $(call hl,CONFIG_RSA_COLOURS=n).\n"

