ifeq ($(PROFILING),1)
FILE=/tmp/make.profiling

define Profiling/Start
	mpstat -u 1 3600 > ${FILE}&
endef

define Profiling/Stop
	killall mpstat
	gnuplot tools/scripts/profiling
endef
endif
