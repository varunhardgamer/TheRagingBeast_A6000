/*
 *  linux/drivers/cpufreq/cpufre.c
 *
 *  Copyright (C) 2001 Russell King
 *            (C) 2002 - 2003 Dominik Brodowski <linux@brodo.de>
 *            (C) 2013 Viresh Kumar <viresh.kumar@linaro.org>
 *
 *  Oct 2005 - Ashok Raj <ashok.raj@intel.com>
 *	Added handling for CPU hotplug
 *  Feb 2006 - Jacob Shin <jacob.shin@amd.com>
 *	Fix handling for CPU hotplug -- affected CPUs
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/cpu.h>
#include <linux/cpufreq.h>
#include <linux/delay.h>
#include <linux/device.h>
#include <linux/init.h>
#include <linux/kernel_stat.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/syscore_ops.h>
#include <linux/tick.h>
#include <trace/events/power.h>
#include <linux/pm_opp.h>

#ifdef CONFIG_VOLTAGE_CONTROL
extern ssize_t cpu_clock_get_vdd(char *buf);
extern ssize_t cpu_clock_set_vdd(const char *buf, size_t count);

static ssize_t show_UV_mV_table(struct cpufreq_policy *policy, char *buf)
{
	return cpu_clock_get_vdd(buf);
}

static ssize_t store_UV_mV_table(struct cpufreq_policy *policy,
	const char *buf, size_t count)
{
	return cpu_clock_set_vdd(buf, count);
}
#endif

extern ssize_t vc_get_vdd(char *buf);

#ifdef CONFIG_VOLTAGE_CONTROL
cpufreq_freq_attr_rw(UV_mV_table);
#endif

#ifdef CONFIG_VOLTAGE_CONTROL
static struct attribute *default_attrs[] = {
	&UV_mV_table.attr,
};
#endif


