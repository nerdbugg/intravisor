include ../../../config.mak

#CC_CHERI_FLAGS += -v

CFLAGS=-fPIC -fPIE -g -nostdinc -ffreestanding
LDFLAGS=-fuse-ld=lld -nostdlib

ifneq ($(MODE),sim)
endif

DEPS = 
OBJ = hc_test.o tramps.o hostcalls.o crt.o

default: libhc_test_debug.so

%.o: %.c $(DEPS)
	$(CC_CHERI) $(CC_CHERI_FLAGS) -c -o $@ $< $(CFLAGS)

crt.o: crt.S
	$(CC_CHERI) $(CC_CHERI_FLAGS) $(CFLAGS) -c -o $@ $^

tramps.o: tramps.S
	$(CC_CHERI) $(CC_CHERI_FLAGS) $(CFLAGS) -c -o $@ $^

bypass.o: bypass.S
	$(CC_CHERI) $(CC_CHERI_FLAGS) $(CFLAGS) -c -o $@ $^

libhc_test.so: $(OBJ)
	$(CC_CHERI) $(CC_CHERI_FLAGS) $(LDFLAGS) -o $@ -fPIE -fPIC $(OBJ)

libhc_test_debug.so: libhc_test.so
	$(CC_CHERI) $(CC_CHERI_FLAGS) $(LDFLAGS) -o $@ -Wl,--image-base,0x20000000 -fPIE -fPIC $(OBJ)
	$(CC_CHERI) $(CC_CHERI_FLAGS) $(LDFLAGS) -o libhc_test_debug3.so -Wl,--image-base,0x30000000 -fPIE -fPIC $(OBJ)

clean:
	rm -rf ./*.o ./*.so

