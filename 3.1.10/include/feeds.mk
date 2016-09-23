
feeds_list := bmon chillispot clearsilver dhcp6-client \
	ethtool igmpproxy iperf iptraf ip6calc lighttpd \
	miniupnpd mtd-utils net-tools-netstat ntfs-3g \
	openntpd p910nd picocom procps radvd ser2net \
	rp-pppoe-client samba-server strace syslog-ng tcpdump ushare \
	wide-dhcpv6-client xl2tpd yaddns ngrep powertop fuzz
feeds	:= atheros broadcom cavium d2tech efixo realtek packages

md5	:= $(shell echo "$(feeds_list)\
		$(foreach f,$(feeds),$(shell find $(f)/* -prune -type d))"\
       		| md5sum | awk '{print $$1}')

$(STAMP_DIR):
	mkdir $@

openwrt/feeds:
openwrt/package/feeds:
$(STAMP_DIR)/feeds.$(md5): $(STAMP_DIR) openwrt/feeds openwrt/package/feeds
	@$(call Exec,$(RM) $(OPENWRT_DIR)/tmp $(OPENWRT_DIR)/feeds $(OPENWRT_DIR)/package/feeds)
	@$(call Exec,$(OPENWRT_DIR)/scripts/feeds update -a)
	@$(call Exec,$(OPENWRT_DIR)/scripts/feeds install -p efixo -a)
	@$(call Exec,$(OPENWRT_DIR)/scripts/feeds install -p atheros -a)
	@$(call Exec,$(OPENWRT_DIR)/scripts/feeds install -p broadcom -a)
	@$(call Exec,$(OPENWRT_DIR)/scripts/feeds install -p packages $(feeds_list))
	@touch $@

$(STAMP_DIR)/feeds.md5: $(STAMP_DIR)/feeds.$(md5)
	@touch $@
