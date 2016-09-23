obj-y		+= clk.o cpu.o cs.o gpio.o irq.o prom.o setup.o timer.o \
		   dev-dsp.o dev-enet.o dev-pcmcia.o dev-uart.o dev-wdt.o \
		   dev-usb-ohci.o dev-usb-ehci.o dev-usb-udc.o dev-spi.o
obj-$(CONFIG_EARLY_PRINTK)	+= early_printk.o
obj-$(CONFIG_BCM63XX_PCIE)	+= pcie.o
obj-$(CONFIG_BCM63XX_WLAN)	+= dev-wlan.o
obj-$(CONFIG_BCM63XX_FAP)	+= dev-fap.o
obj-$(CONFIG_BOARD_NEUFBOX4)	+= pcmcia.o
obj-$(CONFIG_BOARD_NEUFBOX6)	+= dev-tdm.o
obj-$(CONFIG_BOARD_NEUFBOX6)	+= dev-si32176.o
obj-$(CONFIG_BOARD_NEUFBOX6)	+= dev-hsspi.o
obj-$(CONFIG_BOARD_NEUFBOX4)	+= bcm-api.o
obj-y		+= c++-support.o

obj-y		+= boards/

EXTRA_CFLAGS += -Werror
