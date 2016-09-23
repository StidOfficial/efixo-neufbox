lib_LTLIBRARIES = libnbd.la
libnbd_la_SOURCES = core.c
if EVENT_PLUGIN
libnbd_la_SOURCES += event.c
endif
if STATUS_PLUGIN
libnbd_la_SOURCES += status.c
endif
if NVRAM_PLUGIN
libnbd_la_SOURCES += nvram.c
endif
if LEDS_PLUGIN
libnbd_la_SOURCES += leds.c
endif
if NBCTL_PLUGIN
libnbd_la_SOURCES += nbctl.c
endif
if AUTOCONF_PLUGIN
libnbd_la_SOURCES += autoconf.c
endif
if SPY_PLUGIN
libnbd_la_SOURCES += spy.c
endif
if FIREWALL_PLUGIN
libnbd_la_SOURCES += firewall.c
endif
if NAT_PLUGIN
libnbd_la_SOURCES += nat.c
endif
if UROUTE_PLUGIN
libnbd_la_SOURCES += uroute.c
endif
if UPING_PLUGIN
libnbd_la_SOURCES += uping.c
endif
if UTRACEROUTE_PLUGIN
libnbd_la_SOURCES += utraceroute.c
endif
if LAN_PLUGIN
libnbd_la_SOURCES += lan.c
endif
if WLAN_PLUGIN
libnbd_la_SOURCES += wlan.c
endif
if HOTSPOT_PLUGIN
libnbd_la_SOURCES += hotspot.c
endif
if VOIP_PLUGIN
libnbd_la_SOURCES += voip.c
endif
if STB_PLUGIN
libnbd_la_SOURCES += stb.c
endif
if IGMP_PLUGIN
libnbd_la_SOURCES += igmp.c
endif
if BACKUP3G_PLUGIN
libnbd_la_SOURCES += backup3g.c
endif
if PLC_PLUGIN
libnbd_la_SOURCES += plc.c
endif
if DSL_PLUGIN
libnbd_la_SOURCES += dsl.c
endif
if SFP_PLUGIN
libnbd_la_SOURCES += sfp.c
endif
if VSSTEST_PLUGIN
libnbd_la_SOURCES += vSStest.c
endif
if DDNSCTL_PLUGIN
libnbd_la_SOURCES += ddnsctl.c
endif
if SAMBACTL_PLUGIN
libnbd_la_SOURCES += sambactl.c
endif
if USHARECTL_PLUGIN
libnbd_la_SOURCES += usharectl.c
endif

libnbd_la_CFLAGS = -std=c99
INCLUDES=-I./include/nbd
