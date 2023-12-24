#todo: track changes in headers
include ../config.mak

all:

OBJDIR := build
SRC_LKL := lkl_wrap/iomem.c lkl_wrap/jmp_buf.c lkl_wrap/posix-host.c lkl_wrap/virtio_net_fd.c main.c
SRC_YAML := libyaml/src/api.c libyaml/src/dumper.c libyaml/src/emitter.c libyaml/src/loader.c libyaml/src/parser.c libyaml/src/reader.c libyaml/src/scanner.c libyaml/src/writer.c libyaml/intra_parser.c libyaml/intravisor.c
SRC_LOADER := load_elf/load_elf.c
SRC_COMMON := common/utils.c common/profiler.c
SRC_TFORK := tfork/tfork.c
SRC_CVM := cvm/init.c cvm/restore.c cvm/template.c
SRC_IMAGE := $(wildcard image/*.c)
SRC_DAEMON := daemon.c
SRC_HOSTCALL := hostcalls/hostcalls.c hostcalls/carrie_thread.c hostcalls/host_cap_calls.c hostcalls/host_cap_files.c \
		hostcalls/host_syscall_callbacs.c hostcalls/hostcall_tracer.c hostcalls/host_sc.c \
		hostcalls/fs/fd.c

CFILES  := $(SRC_LKL)  $(SRC_LOADER) $(SRC_YAML) $(SRC_TFORK) $(SRC_CVM) $(SRC_DAEMON) $(SRC_HOSTCALL) $(SRC_COMMON) \
		$(SRC_IMAGE)
ASFILES := arch/riscv/asm.S
CFLAGS	:= -I . -I lkl_wrap/include -I load_elf/ -I tfork/ -I lkl_wrap -I libyaml/include -Ilibyaml/src -DHAVE_CONFIG_H -Ilibyaml/ \
	   -I arch/$(TARGET_ARCH)/include -I image\
		 -DTARGET_ARCH="$(TARGET_ARCH)" -D$(TARGET_ARCH) -DCVM_MAX_SIZE=$(CONFIG_CVM_MAX_SIZE)
CFLAGS += -DEXTRA_PAYLOAD="(1*1024*1024)"

CFLAGS += -DHYB_CVM

ifdef TFORK
  CFLAGS += -DTFORK
endif

ifdef DEBUG
  CFLAGS += -DDEBUG
else
	CFLAGS += -O2 -fno-omit-frame-pointer
endif

ifdef MMAP_COMBINE
	CFLAGS += -DMMAP_COMBINE
endif

ifdef META_CACHE
	CFLAGS += -DMETA_CACHE
endif

ifdef HC_TRACE
  CFLAGS += -DHC_TRACE
endif

# use make CONFIG=1 --ignore-errors to generate compile_commands.json
ifdef CONFIG
  CFLAGS += -include fake_header/cheri_builtin.h
  # TODO: set a fake $(CC) rather than use --ignore-errors?
endif

ifdef PROFILER_US
	CFLAGS += -DPROFILER_US
endif

target_c = ${OBJDIR}/$(patsubst %.c,%.o,$(notdir ${1})) 
target_s = ${OBJDIR}/$(patsubst %.S,%.o,$(notdir ${1})) 
obj.c :=
obj.S :=
define obj_c
  $(call target_c,${1}) : ${1} | ${OBJDIR}
  obj$(suffix ${1}) += $(call target_c,${1})
endef

define obj_s
  $(call target_s,${1}) : ${1} | ${OBJDIR}
  obj$(suffix ${1}) += $(call target_s,${1})
endef

define SOURCES_C
  $(foreach src,${1},$(eval $(call obj_c,${src})))
endef

define SOURCES_S
  $(foreach src,${1},$(eval $(call obj_s,${src})))
endef


$(eval $(call SOURCES_C,${CFILES}))
$(eval $(call SOURCES_S,${ASFILES}))

all : ${OBJDIR} ${obj.c} ${obj.S} monitor

${obj.c} : % :
	$(CC_MON) $(CC_MON_FLAGS) $(CFLAGS) -c -o $@ $^

${obj.S} : % :
	$(AS_MON) $(AS_MON_FLAGS) -c -o $@ $^

${OBJDIR} :
	mkdir $@

monitor : ${OBJDIR} 
	$(CC_MON) $(CC_MON_FLAGS) -fuse-ld=lld -ldl -lrt -lm -lpthread -o ${OBJDIR}/monitor ${obj.c} ${obj.S} 

clean:
	rm -rf ${OBJDIR}

all: monitor

.PHONY: all clean
