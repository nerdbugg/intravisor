CHERI_SDK=$(HOME)/cheri/output/sdk

TARGET_ARCH=riscv

CONFIG_CVM_MAX_SIZE = 0x10000000

#MONITOR
CC_MON = $(CHERI_SDK)/bin/clang
#CC_MON_FLAGS = -g -target riscv64-unknown-freebsd --sysroot="$(CHERI_SDK)/sysroot-riscv64-hybrid" -fuse-ld=lld -mno-relax -march=rv64gcxcheri -mabi=lp64d
CC_MON_FLAGS = -g -target riscv64-unknown-freebsd --sysroot="$(CHERI_SDK)/sysroot-riscv64-hybrid" -mno-relax -march=rv64gcxcheri -mabi=lp64d

AS_MON = $(CHERI_SDK)/bin/clang
#AS_MON_FLAGS = -g -target riscv64-unknown-freebsd --sysroot="$(CHERI_SDK)/sysroot-riscv64-hybrid" -fuse-ld=lld -mno-relax -march=rv64gcxcheri -mabi=lp64d
AS_MON_FLAGS = -g -target riscv64-unknown-freebsd --sysroot="$(CHERI_SDK)/sysroot-riscv64-hybrid" -mno-relax -march=rv64gcxcheri -mabi=lp64d

#musl-lkl

#don't use objcopy from this sdk, it doesn't set  ELF OS/ABI field for binary->ELF conversion
#CROSS_COMPILE="$(CHERI_SDK)/bin/"
CROSS_COMPILE=riscv64-linux-gnu-
CC=$(CHERI_SDK)/bin/clang
CC_SYSROOT=--sysroot=\"$(CHERI_SDK)/sysroot-riscv64-hybrid\"
CC_FLAGS = -target riscv64-unknown-linux -fPIE -mno-relax --sysroot="$(CHERI_SDK)/sysroot-riscv64-hybrid"

CC_CHERI = $(CHERI_SDK)/bin/clang
CC_CHERI_FLAGS = -target riscv64-unknown-linux -fPIE -mno-relax --sysroot="$(CHERI_SDK)/sysroot-riscv64-hybrid" -march=rv64gcxcheri -mabi=lp64d

CC_CHERI_PURE = $(CHERI_SDK)/bin/clang
CC_CHERI_PURE_FLAGS = -target riscv64-unknown-linux -fPIE -mno-relax --sysroot="$(CHERI_SDK)/sysroot-riscv64-hybrid" -march=rv64gcxcheri -mabi=l64pc128d

