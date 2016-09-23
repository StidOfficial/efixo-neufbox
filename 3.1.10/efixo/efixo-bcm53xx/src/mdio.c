
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <syslog.h>
#include <errno.h>

#include <unistd.h>
#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include <net/if.h>
#include <linux/mii.h>
#include <linux/sockios.h>

#define fatal(fmt, ...) \
do { \
	fprintf(stderr, "%s::%d$ "fmt " [code: %d, %m]\n", __func__, __LINE__, ##__VA_ARGS__, errno); \
	exit(EXIT_FAILURE); \
} while (0)

#define trace(fmt, ...) \
do { \
	printf(fmt"\n", ##__VA_ARGS__); \
} while (0)

#define min(x, y) \
({ \
    typeof(x) _x = (x);    \
    typeof(y) _y = (y);    \
   ( void ) (&_x == &_y);        \
    _x < _y ? _x : _y; \
})

#define max(x, y) \
({ \
    typeof(x) _x = (x);    \
    typeof(y) _y = (y);    \
   ( void ) (&_x == &_y);        \
    _x > _y ? _x : _y; \
})

#define matches( s, c_str ) \
({ \
	const char __dummy[] = c_str; \
	(void)(&__dummy); \
	( memcmp ( s, c_str, sizeof( c_str ) ) == 0 ); \
})

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

#define __packed __attribute__ ((__packed__))
#define __noreturn __attribute__ ((__noreturn__))

static struct ifreq ifr;
static struct mii_ioctl_data *mii =
    (struct mii_ioctl_data *)(unsigned long)&ifr.ifr_data;

static int bcm53xx_open(char const *ifname, int phyid)
{
	int fd = 0;

	if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		syslog(LOG_PERROR, "%s( %d, %d, 0 )", "socket", AF_INET,
		       SOCK_DGRAM);
		return -1;
	}

	memset(mii, 0x00, sizeof(*mii));
	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", ifname);
	ioctl(fd, SIOCGMIIPHY, &ifr);
	printf("phyid: %x force %x\n", mii->phy_id, phyid);
	mii->phy_id = 0x08;

	return fd;
}

static void bcm53xx_close(int fd)
{
	close(fd);
}

static uint16_t bcm53xx_mdio_read(int fd, int regnum)
{
	mii->reg_num = regnum;

	if (ioctl(fd, SIOCGMIIREG, &ifr) < 0) {
		syslog(LOG_PERROR, "SIOCGMIIREG");
		return -1;
	}

	return mii->val_out;
}

static void bcm53xx_mdio_write(int fd, unsigned regnum, uint16_t value)
{
	mii->reg_num = regnum;
	mii->val_in = value;

	if (ioctl(fd, SIOCSMIIREG, &ifr) < 0)
		syslog(LOG_PERROR, "SIOCSMIIREG,");
}

static __noreturn void usage(char const *name)
{
	fatal("%s: <ifname> <phyid> <register> [value]\n", name);
}

int main(int argc, char *argv[])
{
	int fd;
	int phyid;
	unsigned long reg;
	unsigned long value;

	if (argc < 4)
		usage(argv[0]);

	phyid = strtoul(argv[2], NULL, 0);
	fd = bcm53xx_open(argv[1], phyid);

	reg = strtoul(argv[3], NULL, 0);
	if (argc == 5) {
		value = strtoul(argv[4], NULL, 0);
		bcm53xx_mdio_write(fd, reg, value);
	}
	value = bcm53xx_mdio_read(fd, reg);
	bcm53xx_close(fd);

	trace("mdio [%02lxh] : %04lxh", reg, value);

	bcm53xx_close(fd);

	return 0;
}
