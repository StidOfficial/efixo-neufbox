#include "ddnsctl.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "core.h"

int nbd_ddnsctl_start(void)
{
	return nbd_set("ddnsctl", "start");
}

int nbd_ddnsctl_stop(void)
{
	return nbd_set("ddnsctl", "stop");
}

int nbd_ddnsctl_restart(void)
{
	return nbd_set("ddnsctl", "restart");
}

int nbd_ddnsctl_status(char **xml, size_t * size)
{
	return nbd_get_new(xml, size, "ddnsctl", "status");
}
