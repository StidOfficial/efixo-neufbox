
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <unistd.h>

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <linux/gpio_dev.h>
#include <linux/ioctl.h>

void gpio_direction_input(int gpio)
{
	int fd;

	fd = open("/dev/gpio", O_RDWR);
	if (fd < 0) {
		return;
	}

	ioctl(fd, GPIO_DIR_IN, gpio);

	close(fd);
}

void gpio_direction_output(int gpio)
{
	int fd;

	fd = open("/dev/gpio", O_RDWR);
	if (fd < 0) {
		return;
	}

	ioctl(fd, GPIO_DIR_OUT, gpio);

	close(fd);
}

int gpio_get_value(int gpio)
{
	int fd;
	int value;

	fd = open("/dev/gpio", O_RDWR);
	if (fd < 0) {
		return -1;
	}

	value = ioctl(fd, GPIO_GET, gpio);

	close(fd);

	return value;
}

void gpio_set_value(int gpio, int value)
{
	int fd;

	fd = open("/dev/gpio", O_RDWR);
	if (fd < 0) {
		return;
	}

	ioctl(fd, value ? GPIO_SET : GPIO_CLEAR, gpio);

	close(fd);
}
