#!/system/bin/sh
# SPECTRUM KERNEL MANAGER
# Profile initialization script by nathanchance

echo 1 > /sys/module/process_reclaim/parameters/enable_process_reclaim
echo 70 > /sys/module/process_reclaim/parameters/pressure_max
echo 30 > /sys/module/process_reclaim/parameters/swap_opt_eff
# Kill Almk
echo 0 > /sys/module/lowmemorykiller/parameters/enable_adaptive_lmk
# Do your left over job u script
echo 50 > /sys/module/process_reclaim/parameters/pressure_min
echo 512 > /sys/module/process_reclaim/parameters/per_swap_size
echo "18432,23040,27648,32256,36864,46080" > /sys/module/lowmemorykiller/parameters/minfree
echo 53059 > /sys/module/lowmemorykiller/parameters/vmpressure_file_min
echo 2919 > /proc/sys/vm/min_free_kbytes
echo 6075 > /proc/sys/vm/extra_free_kbytes

# If there is not a persist value, we need to set one
if [ ! -f /data/property/persist.spectrum.profile ]; then
    setprop persist.spectrum.profile 2
fi
