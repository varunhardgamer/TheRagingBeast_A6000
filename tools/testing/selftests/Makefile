TARGETS = breakpoints
TARGETS += cpu-hotplug
TARGETS += efivarfs
TARGETS += kcmp
TARGETS += memory-hotplug
TARGETS += mqueue
<<<<<<< HEAD
TARGETS += mount
=======
>>>>>>> 146ce814822a0d5a65e6449572d9afc6e6c08b7c
TARGETS += net
TARGETS += ptrace
TARGETS += vm

all:
	for TARGET in $(TARGETS); do \
		make -C $$TARGET; \
	done;

run_tests: all
	for TARGET in $(TARGETS); do \
		make -C $$TARGET run_tests; \
	done;

clean:
	for TARGET in $(TARGETS); do \
		make -C $$TARGET clean; \
	done;
