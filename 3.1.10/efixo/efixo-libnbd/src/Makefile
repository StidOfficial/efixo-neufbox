#
# $Id: Makefile 18479 2010-11-30 11:22:20Z mgo $
#

PKG:=nbd
VERSION:=1.1.2


srcdirs	:= client lib server server/lib server/lib/hal server/plugins
incdirs	:= lib/include server/include server/include/lib server/include/plugins
dirs 	:= $(srcdirs) $(incdirs)
files	:= $(foreach dir,$(dirs), $(wildcard $(dir)/*.c))
files	+= $(foreach dir,$(dirs), $(wildcard $(dir)/*.h))
files	:= $(filter-out server/include/plugin_list.h, $(files))

CFLAGS		+= -std=gnu99 -D_GNU_SOURCE \
		   -Wall -Wextra -Werror -Wshadow -Wcast-qual \
		   -Wold-style-definition -Wmissing-noreturn \
		   -Wstrict-prototypes -Waggregate-return -Wformat=2 \
		   -Wundef -Wunused-parameter -Wnonnull -Wpointer-arith

#CFLAGS		+= -Wswitch-default -Wconversion -Wunsafe-loop-optimizations

ifdef DEBUG
MAKEFLAGS	+= 'DEBUG=y'
CFLAGS		+= -g -DDEBUG
else
MAKEFLAGS	+=
CFLAGS		+= -DNDEBUG
endif
export CFLAGS

INSTALL_BIN	:= install -m0755
INSTALL_DIR	:= install -d -m0755
export INSTALL_BIN
export INSTALL_DIR

qcheck:
	! (grep -rn nbu_ $(subdirs) | grep -v .svn)
	! (grep -rn " = " $(subdirs) | grep "if (") | grep -v .svn
	touch $@

subdirs	:= lib
.PHONY: all install clean mrproper
all install clean mrproper: qcheck
	@for dir in $(subdirs); do echo "  *** $@ $$dir"; $(MAKE) -C $$dir $@ || exit 1; done

CHECK:=/home/miguel/src/svn/dev/openwrt/build_dir/linux-brcm63xx_nb6-main_nb6-main/linux-2.6.30.10/scripts/checkpatch.pl
.PHONY: indent
indent:
	find -name "*.[c|h]" -exec indent -linux -cp1 -il0 {} \;
	@find -name "*.[c|h]" -exec indent -linux -cp1 -il0 {} \;
	XMLLINT_INDENT="	" find server/plugins/xml/ -name *.xml -exec xmllint --format '{}' --output '{}' \;  
	find -name "*~" -delete

check: indent
	find -name "*.[c|h]" -exec $(CHECK) --file {} \;\
		|grep -v C99\
		|grep -v 'foo \*'\
		|grep -v 'trailing statements should be on next line'\
		|grep -v 'Macros with complex values should be enclosed in parenthesis'\
		|grep "^ERROR:" -A 2 || true
