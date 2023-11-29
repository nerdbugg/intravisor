SYSROOT=$(HOME)/tmp/root/usr/local/riscv64-carrier
CHERI_SDK=$(HOME)/cheri/output/sdk

CC=$(CHERI_SDK)/bin/riscv64-unknown-freebsd-clang
CFLAGS=--target=riscv64-carrier -march=rv64gcxcheri -mabi=lp64d \
	--sysroot=$(HOME)/cheri/output/sdk/sysroot-riscv64-hybrid \
	-fPIC -fPIE -mno-relax -static\
	-U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0  -fno-stack-protector \
	-fno-common \
	-ffreestanding -nostdlib -nostdinc \
	-I $(SYSROOT)/include \
	-I /home/chu/cheri/llvm-project/clang/lib/Headers
CXX=$(CHERI_SDK)/bin/riscv64-unknown-freebsd-c++
LD=$(CHERI_SDK)/bin/riscv64-unknown-freebsd-ld
AS=$(CHERI_SDK)/bin/riscv64-unknown-freebsd-cc -x assembler-with-cpp
AR=$(CHERI_SDK)/bin/riscv64-unknown-freebsd-ar
OC=$(CHERI_SDK)/bin/riscv64-unknown-freebsd-objcopy
OD=$(CHERI_SDK)/bin/riscv64-unknown-freebsd-objdump
RM=rm -fr

LDFLAGS=-fuse-ld=lld -mno-relax -v

LIBDIRS		:= -L ../libonnx/src -L $(SYSROOT)/lib -L $(CHERI_SDK)/sysroot-riscv64-hybrid/lib
LIBS 		:= -lonnx -lm

INCDIRS		:= -I . -I ../libonnx/src
SRCDIRS		:= .

SFILES		:= $(foreach dir, $(SRCDIRS), $(wildcard $(dir)/*.S))
CFILES		:= $(foreach dir, $(SRCDIRS), $(wildcard $(dir)/*.c))
CPPFILES	:= $(foreach dir, $(SRCDIRS), $(wildcard $(dir)/*.cpp))

SDEPS		:= $(patsubst %, %, $(SFILES:.S=.o.d))
CDEPS		:= $(patsubst %, %, $(CFILES:.c=.o.d))
CPPDEPS		:= $(patsubst %, %, $(CPPFILES:.cpp=.o.d))
DEPS		:= $(SDEPS) $(CDEPS) $(CPPDEPS)

SOBJS		:= $(patsubst %, %, $(SFILES:.S=.o))
COBJS		:= $(patsubst %, %, $(CFILES:.c=.o))
CPPOBJS		:= $(patsubst %, %, $(CPPFILES:.cpp=.o)) 
OBJS		:= $(SOBJS) $(COBJS) $(CPPOBJS)

OBJDIRS		:= $(patsubst %, %, $(SRCDIRS))
NAME		:= libmnist.so
VPATH		:= $(OBJDIRS)

.PHONY: all clean

all : $(NAME)

$(NAME) : $(OBJS)
	@echo [LD] Linking $@
	@$(CC) $(CFLAGS) $(LDFLAGS) $(LIBDIRS) $^\
		$(SYSROOT)/lib/libc.a \
		$(SYSROOT)/lib/libm.a \
		$(SYSROOT)/lib/libgloss.a \
		/home/chu/tmp/root/usr/local/riscv64-carrier/lib/crt0.o \
		$(CHERI_SDK)/sysroot-riscv64-hybrid/usr/lib/libcompiler_rt.a \
		-shared \
		-o $@ $(LIBS)
	@$(CC) $(CFLAGS) $(LDFLAGS) -Wl,--image-base,0x20000000 $(LIBDIRS) $^\
		$(SYSROOT)/lib/libc.a \
		$(SYSROOT)/lib/libm.a \
		$(SYSROOT)/lib/libgloss.a \
		/home/chu/tmp/root/usr/local/riscv64-carrier/lib/crt0.o \
		$(CHERI_SDK)/sysroot-riscv64-hybrid/usr/lib/libcompiler_rt.a \
		-shared \
		-o libmnist_debug.so $(LIBS)

$(SOBJS) : %.o : %.S
	@echo [AS] $<
	@$(AS) $(ASFLAGS) -MD -MP -MF $@.d $(INCDIRS) -c $< -o $@

$(COBJS) : %.o : %.c
	@echo [CC] $<
	@$(CC) $(CFLAGS) -MD -MP -MF $@.d $(INCDIRS) -c $< -o $@

$(CPPOBJS) : %.o : %.cpp
	@echo [CXX] $<
	@$(CXX) $(CXXFLAGS) -MD -MP -MF $@.d $(INCDIRS) -c $< -o $@

clean:
	@$(RM) $(DEPS) $(OBJS) $(NAME)

sinclude $(DEPS)

