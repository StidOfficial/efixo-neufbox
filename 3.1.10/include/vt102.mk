ifneq ($(strip $(NO_COLOR)),1)
BLACK	:= \\033[30m
RED	:= \\033[31m
GREEN	:= \\033[32m
BROWN	:= \\033[33m
BLUE	:= \\033[34m
PURPLE	:= \\033[35m
CYAN	:= \\033[36m
GREY	:= \\033[37m
RST	:= \\033[0m
endif

COLOR	?= $(GREEN)

trace	 = printf "$(COLOR)%s$(RST)\n" $(1)
todo	 = printf "$(PURPLE)%s$(RST)\n" $(1)
warn	 = printf "$(RED)%s$(RST)\n" $(1)
