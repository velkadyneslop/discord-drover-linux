CC ?= cc
CFLAGS ?= -O2 -g
# No _FORTIFY_SOURCE: keeps the glibc symbol requirements low so a library built
# on the host also loads inside the (older) Flatpak runtime.
override CFLAGS += -fPIC -Wall -Wextra -std=gnu11 -U_FORTIFY_SOURCE -fno-stack-protector

libdrover.so: drover.c
	$(CC) $(CFLAGS) -shared -o $@ $< -Wl,-z,defs

test: libdrover.so
	python3 tests/test_drover.py

clean:
	rm -f libdrover.so

.PHONY: test clean
