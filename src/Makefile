# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
OUTPUT ?= .output
SRC_DIR ?= .
CLANG ?= clang
LLC ?= llc
LLVM_STRIP ?= llvm-strip
BPFTOOL ?= $(abspath ../tools/bpftool)
LIBBPF_SRC := $(abspath ../libbpf/src)
LIBBPF_OBJ := $(abspath $(OUTPUT)/libbpf.a)
INCLUDES := -I$(OUTPUT)
HIKE_VM_INCLUDES := -I$(abspath $(shell pwd))
CFLAGS := -g -Wall
ARCH := $(shell uname -m | sed 's/x86_64/x86/')

# eBPF programs; add more eBPF programs here.
EBPF_SRC ?= minimal_xdp.bpf.c \
	    minimal_classifier.bpf.c \
	    monitor.bpf.c \
	    ip6_tos_cls.bpf.c

# Hike Chains; add more HIKe Chains here.
HIKE_CHAIN_SRC ?= minimal_chain.hike.c

###############################
###### DO NOT EDIT BELOW ######
###############################

EBPF_OBJ := ${EBPF_SRC:.c=.o}
EBPF_DST_OBJ := $(addprefix $(OUTPUT)/, $(EBPF_OBJ))

HIKE_CHAIN_OBJ := ${HIKE_CHAIN_SRC:.c=.o}
HIKE_CHAIN_DST_OBJ := $(addprefix $(OUTPUT)/, $(HIKE_CHAIN_OBJ))

# Get Clang's default includes on this system. We'll explicitly add these dirs
# to the includes list when compiling with `-target bpf` because otherwise some
# architecture-specific dirs will be "missing" on some architectures/distros -
# headers such as asm/types.h, asm/byteorder.h, asm/socket.h, asm/sockios.h,
# sys/cdefs.h etc. might be missing.
#
# Use '-idirafter': Don't interfere with include mechanics except where the
# build would have failed anyways.
CLANG_BPF_SYS_INCLUDES = $(shell $(CLANG) -v -E - </dev/null 2>&1 \
	| sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }')

ifeq ($(V),1)
	Q =
	msg =
else
	Q = @
	msg = @printf '  %-8s %s%s\n'					\
		      "$(1)"						\
		      "$(patsubst $(abspath $(OUTPUT))/%,%,$(2))"	\
		      "$(if $(3), $(3))";
	MAKEFLAGS += --no-print-directory
endif

.PHONY: all libbpf hikeprog hikechain

all: libbpf prog chain | $(OUTPUT)

chain: $(HIKE_CHAIN_DST_OBJ)
prog: $(EBPF_DST_OBJ)
libbpf: $(LIBBPF_OBJ)

.PHONY: clean
clean:
	$(call msg,CLEAN)
	$(Q)rm -rf $(OUTPUT)

$(OUTPUT) $(OUTPUT)/libbpf:
	$(call msg,MKDIR,$@)
	$(Q)mkdir -p $@

# Build libbpf
$(LIBBPF_OBJ): $(wildcard $(LIBBPF_SRC)/*.[ch] $(LIBBPF_SRC)/Makefile) | $(OUTPUT)/libbpf
	$(call msg,LIB,$@)
	$(Q)$(MAKE) -C $(LIBBPF_SRC) BUILD_STATIC_ONLY=1		      \
		    OBJDIR=$(dir $@)/libbpf DESTDIR=$(dir $@)		      \
		    INCLUDEDIR= LIBDIR= UAPIDIR=			      \
		    install

# Build the absolute SRC path directly from the object filename
abs_src_path = $(addprefix $(SRC_DIR)/,${1:.o=.c})

$(addprefix $(OUTPUT)/,%.bpf.o): $(addprefix $(SRC_DIR)/,%.bpf.c) $(LIBBPF_OBJ) \
				 $(wildcard *.h) vmlinux.h | $(OUTPUT)
	$(call msg,PROG,$@)
	$(Q)$(CLANG) -g						\
		-Wall						\
		-O2 -target bpf 				\
		-D__TARGET_ARCH_$(ARCH)				\
		$(INCLUDES) $(HIKE_VM_INCLUDES)			\
		$(CLANG_BPF_SYS_INCLUDES)			\
		-c $< -o $@
	$(call msg,BTFDMP,$@)
	$(Q)$(BPFTOOL) btf dump file $@ -j -p > ${@:.o=.json}

#	$(CLANG) -S \
#	    -target bpf \
#	    -D __BPF_TRACING__ \
#	    $(INCLUDES) \
#	    $(CLANG_BPF_SYS_INCLUDES) \
#	    $(BPF_CFLAGS) \
#	    -Wall \
#	    -Wno-unused-value \
#	    -Wno-unused-function \
#	    -Wno-pointer-sign \
#	    -Wno-compare-distinct-pointer-types \
#	    -Werror \
#	    -O2 -emit-llvm -c $(@F:.o=.c) -g -o ${@:.o=.ll}
#	$(LLC) -march=bpf -filetype=obj -o $@ ${@:.o=.ll}


# Build the HIKe Chain code (which is eBPF code indeed)
$(addprefix $(OUTPUT)/,%.hike.o): $(addprefix $(SRC_DIR)/,%.hike.c) $(LIBBPF_OBJ) \
				  $(wildcard %.h) vmlinux.h | $(OUTPUT)
	$(call msg,CHAIN,$@)
	$(Q)$(CLANG) -g						\
		-Wall						\
		-O2 -target bpf 				\
		-D__TARGET_ARCH_$(ARCH)				\
		$(INCLUDES) $(HIKE_VM_INCLUDES)			\
		$(CLANG_BPF_SYS_INCLUDES)			\
		-c $< -o $@

#$(Q)$(LLVM_STRIP) -g $@ # strip useless DWARF info

# delete failed targets
.DELETE_ON_ERROR:

# keep intermediate (.skel.h, .bpf.o, etc) targets
.SECONDARY:

