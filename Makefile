CC=arm-vita-eabi-gcc
CFLAGS=-Os -fno-builtin-printf -fPIC -fno-builtin-memset -Wall -Wextra -Wno-unused-variable -DFW_365
OBJCOPY=arm-vita-eabi-objcopy
LDFLAGS=-nodefaultlibs -nostdlib

fat.bin: first.bin second.bin
	./gen.py fat.tpl first.bin second.bin fat.bin

first.bin: first
	$(OBJCOPY) -O binary $^ $@

second.bin: second
	$(OBJCOPY) -O binary $^ $@

first: first.o
	$(CC) -o $@ $^ $(LDFLAGS) -T first.x

second: second.o
	$(CC) -o $@ $^ $(LDFLAGS) -T second.x

clean:
	-rm -f first first.bin second second.bin fat.bin *.o
