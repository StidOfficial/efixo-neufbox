
#include <asm/atomic.h>
#include <linux/types.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/i2c.h>
#include <linux/hwmon.h>
#include <linux/pwm.h>
#include <linux/delay.h>
#include <linux/err.h>
#include <linux/workqueue.h>
#include <linux/hardirq.h>

#define NB6_MCU_DRV_NAME       "nb6-hwmon"
#define DRIVER_VERSION          "1.0"

#define NB6_LEDS_MODE_CMD	0x31

#define UDELAY			1000

/*
 * Driver data (common to all clients)
 */
static const unsigned short normal_i2c[] = { 0x60, I2C_CLIENT_END };

I2C_CLIENT_INSMOD_1(nb6hwmon);

#define LED_OFF		0
#define LED_LOW		7
#define LED_HALF	15
#define LED_FULL	31
#define LED_MASK	0x1f

enum LEDS_ID {
	LED_ID_START = 0x10,
	LED_ID_RED1 = LED_ID_START,
	LED_ID_RED2,
	LED_ID_RED3,
	LED_ID_GREEN1,
	LED_ID_GREEN2,
	LED_ID_GREEN3,
	LED_ID_WAN,
	LED_ID_VOIP,
	LED_ID_WLAN,
	LED_ID_LAST,
};

enum LEDS_MODE {
	LEDS_MODE_DISABLE,
	LEDS_MODE_BOOT,
	LEDS_MODE_BOOT_MAIN,
	LEDS_MODE_BOOT_TFTP,
	LEDS_MODE_BOOT_RESCUE,
	LEDS_MODE_LOGIN,
	LEDS_MODE_BURNING,
	LEDS_MODE_DOWNLOAD,
	LEDS_MODE_WDT_TEMPERATURE,
	LEDS_MODE_WDT_VOLTAGE,
	LEDS_MODE_PANIC,
	LEDS_MODE_CONTROL,
	LEDS_MODE_LAST,
};

struct pwm_device {
	struct work_struct work;
	int id;
	int config;
	int value;
};

union uu16 {
	u16 u16;
	u8 u8[2];
};

struct nb6hwmon_data {
	struct device *hwmon_dev;
	struct mutex lock;
	unsigned long expires;
	union uu16 T;
	union uu16 V;
	struct pwm_device pwm_dev[9];
	u8 mcu_leds_mode;
	u8 pwm_ref_level;
	u8 release;
	u8 wdt_clk;
	u8 stats_boot;
	u8 stats_panic;
	u8 stats_oops;
};

static struct i2c_client *pwm_client = NULL;

static u8 mcu_read_update(struct i2c_client *client, unsigned addr, u8 old)
{
	int status;
	int i;

	for (i = 0; i < 5; ++i) {
		status = i2c_smbus_read_byte_data(client, addr);
		if (status >= 0)
			return status;
		udelay(UDELAY);
	}

	return old;
}

static u8 mcu_read(struct i2c_client *client, unsigned addr)
{
	int status;
	int i;

	for (i = 0; i < 5; ++i) {
		status = i2c_smbus_read_byte_data(client, addr);
		if (status >= 0)
			return status;
		udelay(UDELAY);
	}

	return ~0;
}

static int mcu_write(struct i2c_client *client, int addr, int val)
{
	int status;
	int i;

	for (i = 0; i < 5; ++i) {
		status = i2c_smbus_write_byte_data(client, addr, val);
		if (status > 0)
			return 0;
		udelay(UDELAY);
	}

	return status;
}

/* PWM */
struct pwm_device *pwm_request(int pwm_id, const char *label)
{
	struct nb6hwmon_data *data;
	struct pwm_device *pwm;

	if ((!pwm_client) || (pwm_id < LED_ID_START) || (pwm_id >= LED_ID_LAST))
		return ERR_PTR(-ENOENT);

	data = i2c_get_clientdata(pwm_client);

	pwm = &data->pwm_dev[pwm_id - LED_ID_START];

	return pwm;
}
EXPORT_SYMBOL(pwm_request);

void pwm_free(struct pwm_device *pwm)
{
}
EXPORT_SYMBOL(pwm_free);

static void pwm_work(struct work_struct *work)
{
	struct pwm_device *pwm =
	    (void *)container_of(work, struct pwm_device, work);
	struct nb6hwmon_data *data = i2c_get_clientdata(pwm_client);

	mutex_lock(&data->lock);
	mcu_write(pwm_client, pwm->id, pwm->value);
	mutex_unlock(&data->lock);
}

int pwm_config(struct pwm_device *pwm, int duty_ns, int period_ns)
{
	struct nb6hwmon_data *data;

	pwm->config = duty_ns;
	if (duty_ns) {
		if (!pwm_client)
			return -1;
		data = i2c_get_clientdata(pwm_client);
		duty_ns &= ~LED_MASK;
		duty_ns |= data->pwm_ref_level;
	}

	if (xchg(&pwm->value, duty_ns) == duty_ns)
		return 0;

	if (in_atomic())
		schedule_work(&pwm->work);
	else
		pwm_work(&pwm->work);

	return 0;
}
EXPORT_SYMBOL(pwm_config);

int pwm_get_config(struct pwm_device *pwm)
{
	return pwm->config;
}
EXPORT_SYMBOL(pwm_get_config);

int pwm_enable(struct pwm_device *pwm)
{
	return 0;
}
EXPORT_SYMBOL(pwm_enable);

void pwm_disable(struct pwm_device *pwm)
{
}
EXPORT_SYMBOL(pwm_disable);

/* leds control */
void leds_config(u8 id, u8 value)
{
	struct pwm_device *pwm;

	pwm = pwm_request(id, NULL);
	if (!IS_ERR(pwm)) {
		pwm_config(pwm, value, 0);
		pwm_free(pwm);
	}
}
EXPORT_SYMBOL(leds_config);

static void leds_set_mode(struct nb6hwmon_data *data, u8 mode)
{
	if (mode >= LEDS_MODE_LAST)
		return;

	if (data->mcu_leds_mode != mode) {
		data->mcu_leds_mode = mode;
		mcu_write(pwm_client, NB6_LEDS_MODE_CMD, mode);
	}
}

static void leds_sync(void)
{
	struct nb6hwmon_data *data;
	int id;

	if (!pwm_client)
		return;

	data = i2c_get_clientdata(pwm_client);

	/* update leds */
	for (id = LED_ID_START; id < LED_ID_LAST; ++id)
		leds_config(id, data->pwm_dev[id - LED_ID_START].config);
}

/* leds mode */
static char const *leds_modes_str[] = {
	[LEDS_MODE_DISABLE] = "disable",
	[LEDS_MODE_BOOT] = "boot",
	[LEDS_MODE_BOOT_MAIN] = "boot-main",
	[LEDS_MODE_BOOT_TFTP] = "boot-tftp",
	[LEDS_MODE_BOOT_RESCUE] = "boot-rescue",
	[LEDS_MODE_LOGIN] = "login",
	[LEDS_MODE_BURNING] = "burning",
	[LEDS_MODE_DOWNLOAD] = "downloading",
	[LEDS_MODE_WDT_TEMPERATURE] = "wdt-temperature",
	[LEDS_MODE_WDT_VOLTAGE] = "wdt-voltage",
	[LEDS_MODE_PANIC] = "panic",
	[LEDS_MODE_CONTROL] = "control",
};

static ssize_t show_leds_mode(struct device *dev, struct device_attribute *attr,
			      char *buf)
{
	struct i2c_client *client = to_i2c_client(dev);
	struct nb6hwmon_data *data = i2c_get_clientdata(client);
	int i;
	loff_t off = 0;
	u8 leds_mode = data->mcu_leds_mode;

	for (i = 0; i < ARRAY_SIZE(leds_modes_str); ++i) {
		off +=
		    sprintf(buf + off, i == leds_mode ? "[%s] " : "%s ",
			    leds_modes_str[i]);
	}

	off += sprintf(buf + off, "\n");

	return off;
}

static ssize_t set_leds_mode(struct device *dev, struct device_attribute *attr,
			     const char *buf, size_t count)
{
	char _s[32];
	char *s;
	int i;

	snprintf(_s, sizeof(_s), "%s", buf);
	s = strstrip(_s);
	for (i = 0; i < ARRAY_SIZE(leds_modes_str); ++i) {
		if (!strcmp(s, leds_modes_str[i])) {
			struct i2c_client *client = to_i2c_client(dev);
			struct nb6hwmon_data *data = i2c_get_clientdata(client);

			mutex_lock(&data->lock);
			leds_set_mode(data, i);
			mutex_unlock(&data->lock);
			break;
		}
	}

	return count;
}

static ssize_t show_leds_pwm(struct device *dev, struct device_attribute *attr,
			     char *buf)
{
	struct i2c_client *client = to_i2c_client(dev);
	struct nb6hwmon_data *data = i2c_get_clientdata(client);
	loff_t off = 0;

	mutex_lock(&data->lock);
	if (data->pwm_ref_level == LED_OFF)
		off += sprintf(buf + off, "off\n");
	else if (data->pwm_ref_level == LED_LOW)
		off += sprintf(buf + off, "low\n");
	else if (data->pwm_ref_level == LED_HALF)
		off += sprintf(buf + off, "half\n");
	else if (data->pwm_ref_level == LED_FULL)
		off += sprintf(buf + off, "full\n");
	else
		off += sprintf(buf + off, "%u\n", data->pwm_ref_level);
	mutex_unlock(&data->lock);

	return off;
}

static ssize_t set_leds_pwm(struct device *dev, struct device_attribute *attr,
			    const char *buf, size_t count)
{
	struct i2c_client *client = to_i2c_client(dev);
	struct nb6hwmon_data *data = i2c_get_clientdata(client);
	char _s[32];
	char *s;

	snprintf(_s, sizeof(_s), "%s", buf);
	s = strstrip(_s);

	mutex_lock(&data->lock);
	if (!strcmp(s, "off")) {
		data->pwm_ref_level = LED_OFF;
		leds_set_mode(data, LEDS_MODE_CONTROL);
	} else if (!strcmp(s, "low")) {
		data->pwm_ref_level = LED_LOW;
		leds_set_mode(data, LEDS_MODE_CONTROL);
	} else if (!strcmp(s, "half")) {
		data->pwm_ref_level = LED_HALF;
		leds_set_mode(data, LEDS_MODE_CONTROL);
	} else if (!strcmp(s, "full")) {
		data->pwm_ref_level = LED_FULL;
		leds_set_mode(data, LEDS_MODE_CONTROL);
	}
	mutex_unlock(&data->lock);

	leds_sync();

	return count;
}

/* dmesg */
static ssize_t show_dmesg(struct device *dev, struct device_attribute *attr,
			  char *buf)
{
	struct i2c_client *client = to_i2c_client(dev);
	struct nb6hwmon_data *data = i2c_get_clientdata(client);
	int i;

	mutex_lock(&data->lock);
	mcu_write(client, 0x26, 0);
	for (i = 0; i < 512; ++i, ++buf)
		*buf = mcu_read(client, 0x27);
	mutex_unlock(&data->lock);

	*buf = '\0';

	return i + 1;
}

/* reset */
static ssize_t set_board_reset(struct device *dev,
			       struct device_attribute *attr, const char *buf,
			       size_t count)
{
	struct i2c_client *client = to_i2c_client(dev);
	struct nb6hwmon_data *data = i2c_get_clientdata(client);

	mutex_lock(&data->lock);
	mcu_write(client, 0xee, 0);
	mutex_unlock(&data->lock);

	return count;
}

/*
 * (x100, x1000, x.001, x.0001) prevent floating point
 */
#define ADC_quantum(Vref)	((1000 * (Vref)) / 1024)
#define ADC_mV(Vref,x)		((ADC_quantum(Vref) * (x)) / 1000)

#define ADC_Temperature(t)	(1000 * (100 * ADC_mV(1800, t)) / 349)

#define MR1			82
#define MR2			20
#define ADC_Voltage(v)		((ADC_mV(2400, v) * ((10 * (MR1 + MR2)) / MR2)) / 10)

static void mcu_sync(struct i2c_client *client, struct nb6hwmon_data *data)
{
	udelay(UDELAY);
	data->T.u8[0] = mcu_read_update(client, 0x22, data->T.u8[0]);
	udelay(UDELAY);
	data->T.u8[1] = mcu_read_update(client, 0x23, data->T.u8[1]);
	udelay(UDELAY);
	data->V.u8[0] = mcu_read_update(client, 0x24, data->V.u8[0]);
	udelay(UDELAY);
	data->V.u8[1] = mcu_read_update(client, 0x25, data->V.u8[1]);
	data->expires = jiffies + 3 * HZ;
}

/* temperature */
static ssize_t show_temperature(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	struct i2c_client *client = to_i2c_client(dev);
	struct nb6hwmon_data *data = i2c_get_clientdata(client);
	u16 v;

	mutex_lock(&data->lock);
	if (time_after(jiffies, data->expires)) {
		mcu_sync(client, data);
	}
	v = data->T.u16;
	mutex_unlock(&data->lock);

	return sprintf(buf, "%u\n", ADC_Temperature(v));
}

/* voltage */
static ssize_t show_voltage(struct device *dev, struct device_attribute *attr,
			    char *buf)
{
	struct i2c_client *client = to_i2c_client(dev);
	struct nb6hwmon_data *data = i2c_get_clientdata(client);
	u16 v;

	mutex_lock(&data->lock);
	if (time_after(jiffies, data->expires)) {
		mcu_sync(client, data);
	}
	v = data->V.u16;
	mutex_unlock(&data->lock);

	return sprintf(buf, "%u\n", ADC_Voltage(v));
}

/* release */
static ssize_t show_release(struct device *dev, struct device_attribute *attr,
			    char *buf)
{
	struct i2c_client *client = to_i2c_client(dev);
	struct nb6hwmon_data *data = i2c_get_clientdata(client);

	mutex_lock(&data->lock);
	data->release = mcu_read_update(client, 0x90, data->release);
	mutex_unlock(&data->lock);

	return sprintf(buf, "%u\n", data->release);
}

/* stats */
static ssize_t show_stats(struct device *dev, struct device_attribute *attr,
			  char *buf)
{
	struct i2c_client *client = to_i2c_client(dev);
	struct nb6hwmon_data *data = i2c_get_clientdata(client);

	mutex_lock(&data->lock);
	data->stats_boot = mcu_read_update(client, 0xa0, data->stats_boot);
	data->stats_panic = mcu_read_update(client, 0xa1, data->stats_panic);
	data->stats_oops = mcu_read_update(client, 0xa2, data->stats_oops);
	mutex_unlock(&data->lock);

	return sprintf(buf, "boot: %u\npanic: %u\noops: %u\n", data->stats_boot,
		       data->stats_panic, data->stats_oops);
}

/* watchdog */
static ssize_t show_watchdog(struct device *dev, struct device_attribute *attr,
			     char *buf)
{
	struct i2c_client *client = to_i2c_client(dev);
	struct nb6hwmon_data *data = i2c_get_clientdata(client);

	mutex_lock(&data->lock);
	data->wdt_clk = mcu_read_update(client, 0xee, data->wdt_clk);
	mutex_unlock(&data->lock);

	return sprintf(buf, "%u\n", data->wdt_clk);
}

static ssize_t set_watchdog(struct device *dev,
			    struct device_attribute *attr, const char *buf,
			    size_t count)
{
	struct i2c_client *client = to_i2c_client(dev);
	struct nb6hwmon_data *data = i2c_get_clientdata(client);

	data->wdt_clk = simple_strtoul(buf, NULL, 10);

	mutex_lock(&data->lock);
	mcu_write(client, 0xee, data->wdt_clk);
	mutex_unlock(&data->lock);

	return count;
}

static DEVICE_ATTR(leds_mode, S_IRUGO | S_IWUGO, show_leds_mode, set_leds_mode);
static DEVICE_ATTR(leds_pwm, S_IRUGO | S_IWUGO, show_leds_pwm, set_leds_pwm);
static DEVICE_ATTR(dmesg, S_IRUGO, show_dmesg, NULL);
static DEVICE_ATTR(board_reset, S_IWUGO, NULL, set_board_reset);
static DEVICE_ATTR(temperature, S_IRUGO, show_temperature, NULL);
static DEVICE_ATTR(voltage, S_IRUGO, show_voltage, NULL);
static DEVICE_ATTR(release, S_IRUGO, show_release, NULL);
static DEVICE_ATTR(stats, S_IRUGO, show_stats, NULL);
static DEVICE_ATTR(watchdog, S_IRUGO | S_IWUGO, show_watchdog, set_watchdog);

static struct attribute *nb6_sensors_attributes[] = {
	&dev_attr_leds_mode.attr,
	&dev_attr_leds_pwm.attr,
	&dev_attr_dmesg.attr,
	&dev_attr_board_reset.attr,
	&dev_attr_temperature.attr,
	&dev_attr_voltage.attr,
	&dev_attr_release.attr,
	&dev_attr_stats.attr,
	&dev_attr_watchdog.attr,
	NULL,
};

static const struct attribute_group nb6_attr_grp = {
	.attrs = nb6_sensors_attributes,
};

/*
 * I2C layer
 */

/* Return 0 if detection is successful, -ENODEV otherwise */
static int nb6hwmon_detect(struct i2c_client *client, int kind,
			   struct i2c_board_info *info)
{
	struct i2c_adapter *adapter = client->adapter;

	if (!i2c_check_functionality(adapter, I2C_FUNC_SMBUS_BYTE_DATA))
		return -ENODEV;

	strlcpy(info->type, "nb6hwmon", I2C_NAME_SIZE);
	dev_info(&adapter->dev, "loading %s at %d,0x%02x\n",
		 client->name, i2c_adapter_id(client->adapter), client->addr);
	return 0;
}

/* This function is called by i2c_probe */
static int nb6hwmon_probe(struct i2c_client *client,
			  const struct i2c_device_id *id)
{
	struct nb6hwmon_data *data;
	int err = 0;
	int i;

	if (!(data = kzalloc(sizeof(*data), GFP_KERNEL))) {
		err = -ENOMEM;
		goto exit;
	}

	/* pwm */
	pwm_client = client;

	i2c_set_clientdata(client, data);
	mutex_init(&data->lock);
	data->pwm_ref_level = LED_FULL;
	mcu_sync(client, data);

	/* create the sysfs eeprom file */
	if ((err = sysfs_create_group(&client->dev.kobj, &nb6_attr_grp)))
		goto error_kfree;

	data->hwmon_dev = hwmon_device_register(&client->dev);
	if (IS_ERR(data->hwmon_dev)) {
		err = PTR_ERR(data->hwmon_dev);
		goto error_remove;
	}

	/* setup leds mode to control */
	for (i = LED_ID_START; i < LED_ID_LAST; ++i) {
		struct pwm_device *pwm = &data->pwm_dev[i - LED_ID_START];

		INIT_WORK(&pwm->work, pwm_work);
		pwm->id = i;
		pwm->config = pwm->value = LED_OFF;
		mcu_write(client, pwm->id, pwm->value);
	}

	/* update leds */
	leds_set_mode(data, LEDS_MODE_DISABLE);
	data->pwm_ref_level = LED_FULL;
	leds_set_mode(data, LEDS_MODE_CONTROL);

	return 0;

 error_remove:
	sysfs_remove_group(&client->dev.kobj, &nb6_attr_grp);
 error_kfree:
	kfree(data);
 exit:
	return err;
}

static int nb6hwmon_remove(struct i2c_client *client)
{
	struct nb6hwmon_data *data = i2c_get_clientdata(client);

	pwm_client = NULL;
	hwmon_device_unregister(data->hwmon_dev);
	sysfs_remove_group(&client->dev.kobj, &nb6_attr_grp);
	flush_scheduled_work();

	kfree(data);
	return 0;
}

static const struct i2c_device_id nb6hwmon_id[] = {
	{"nb6hwmon", nb6hwmon},
	{}
};

MODULE_DEVICE_TABLE(i2c, nb6hwmon_id);

static struct i2c_driver nb6hwmon_driver = {
	.class = I2C_CLASS_HWMON,
	.driver = {
		   .name = "nb6hwmon",
		   },
	.probe = nb6hwmon_probe,
	.remove = nb6hwmon_remove,
	.id_table = nb6hwmon_id,
	.detect = nb6hwmon_detect,
	.address_data = &addr_data,
};

static int __init nb6hwmon_init(void)
{
	return i2c_add_driver(&nb6hwmon_driver);
}

static void __exit nb6hwmon_exit(void)
{
	i2c_del_driver(&nb6hwmon_driver);
}

MODULE_AUTHOR("Miguel Gaio <miguel.gaio@efixo.com>");
MODULE_DESCRIPTION("nb6-hwmon: Temperature, Alim sensors");
MODULE_LICENSE("GPL");
MODULE_VERSION(DRIVER_VERSION);

module_init(nb6hwmon_init);
module_exit(nb6hwmon_exit);
