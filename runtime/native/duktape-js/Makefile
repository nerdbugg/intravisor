SYSROOT=$(HOME)/tmp/root/usr/local/riscv64-carrier
CHERI_SDK=$(HOME)/cheri/output/sdk

#CC = riscv64-linux-gnu-gcc-10
#CC = clang --target=riscv64-linux-gnu --sysroot=/usr/riscv64-linux-gnu
CC=$(CHERI_SDK)/bin/riscv64-unknown-freebsd-clang
CFLAGS=--target=riscv64-carrier -march=rv64gcxcheri -mabi=lp64d \
	--sysroot=$(HOME)/cheri/output/sdk/sysroot-riscv64-hybrid \
	-fPIC -fPIE -mno-relax -static\
	-U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0  -fno-stack-protector \
	-fno-common \
	-ffreestanding -nostdlib -nostdinc \
	-I $(SYSROOT)/include \
	-I /home/chu/cheri/llvm-project/clang/lib/Headers
CFLAGS += -MD -mno-relax 
LDFLAGS = -fuse-ld=lld

LIBDIRS		:= -L ../libonnx/src -L $(SYSROOT)/lib -L $(CHERI_SDK)/sysroot-riscv64-hybrid/lib

SRCS = main.c duktape.c
OBJS = main.o duktape.o
PROGRAMS = main

all: main

main.o: main.c

duktape.o: duktape.c

main: main.o duktape.o
	$(CC) $(CFLAGS) $(LDFLAGS) $(LIBDIRS) $^ \
		$(SYSROOT)/lib/libc.a \
		$(SYSROOT)/lib/libm.a \
		$(SYSROOT)/lib/libgloss.a \
		/home/chu/tmp/root/usr/local/riscv64-carrier/lib/crt0.o \
		$(CHERI_SDK)/sysroot-riscv64-hybrid/usr/lib/libcompiler_rt.a \
		-shared \
		-o $@ $(LIBS)

clean:
	rm -f *.o *.d
	rm -f $(PROGRAMS)

-include $(OBJS:.o=.d)

