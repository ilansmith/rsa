CC=gcc
AR=ar
CONFFILE=rsa.mk
LIB_RSA=librsa.a
LIB_RSA_OBJS=rsa_num.o rsa_util.o rsa_stream.o
LIB_RSA_LIC=librsalic.a
LIB_RSA_LIC_OBJS=rsa_crc.o rsa_license.o
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

# enable/disable debug mode (disabled by default)
ifeq ($(CONFIG_DEBUG),y)
  CFLAGS+=-O0 -g
else
  CFLAGS+=-O3
endif

TARGETS=$(TARGET_RSA_LICENSE)
TARGET_OBJS_rsa_license=rsa_license_main.o

%.o: %.c
	$(CC) -o $@ $(CFLAGS) -c $<

.PHONY: all clean cleanapps cleantags cleanconf cleanall config

all: $(TARGETS)
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
	rm -f $(TARGET_RSA_LICENSE)

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
	@printf "This version has been reduced such that only $(call hl,$(TARGET_RSA_LICENSE)) is built.\n"
	@printf "\n"
	@printf "Set $(call hl,CONFIG_MERSENNE_TWISTER=y) (default) to use Takuji Nishimura and Makoto\n"
	@printf "Matsumoto's 64-bit version Mersenne Twister PRNG (Pseudorandom Number Generator).\n"
	@printf "If $(call hl,CONFIG_MERSENNE_TWISTER=n) then random(3) is used as a PRNG instead.\n"
	@printf "\n"
	@printf "Note that different sets of unit tests are enabled for different values of $(call hl,U64).\n"
	@printf "\n"
	$(call help_print_tool,"CONFIG_DEBUG=y","build without optimizations and generate debug symbols")
	@printf "\n"

