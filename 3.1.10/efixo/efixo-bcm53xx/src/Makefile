
all: libbcm53xx.a switch-robo mdio

CFLAGS += -std=gnu99 \
	-Wall -W -Wshadow -Werror \
	-D_GNU_SOURCE -DNDEBUG -I. -I$(LINUX_DIR)/include

CFLAGS += $(if $(findstring nb4,$(BOX)),-DBROADCOM_5325E_SWITCH)
CFLAGS += $(if $(findstring nb5,$(BOX)),-DBROADCOM_5395S_SWITCH)

bcm53xx.o: CFLAGS+=-fpic -DPIC
bcm53xx.o: LDLIBS+=-letk
bcm53xx.o:

libbcm53xx.a: bcm53xx.o
	$(AR) rcs $@ $^

mdio: mdio.o
switch-robo: switch-robo.o bcm53xx.o

indent:
	find -name "*.[c|h]" -exec indent -linux -cp1 -il0 {} \;
	find -name "*~" -delete
