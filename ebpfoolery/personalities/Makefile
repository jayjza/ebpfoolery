# --------------------------------------------------
# Makefile for personalities
# --------------------------------------------------
CLANG = clang
LLC = llc
#DEBUG = y  enables printk in the BPF program
DEBUG ?= n

#Path to include files of respectively libbpf-dev and iproute2
LIBBPF_INCLUDE ?= /usr/include/bpf
IPROUTE_INCLUDE ?= /usr/include/iproute2
ASM_TYPES_INCLUDE ?= /usr/include/$(shell uname -m)-linux-gnu
NET_INCLUDE ?= /lib/modules/$(shell uname -r)/build/include/
KERNEL_HEADERS := /lib/modules/$(shell uname -r)/build

SRC_DIR=.

LIBBPF_DIR ?= /usr/lib/$(shell uname -m)-linux-gnu
#Requires libbpf-dev package
OBJECT_LIBBPF = libbpf.a

CFLAGS ?= -g -static \
		-I$(LIBBPF_INCLUDE) \
		-I $(IPROUTE_INCLUDE) \
		-I ${NET_INCLUDE} \
		-I$(KERNEL_HEADERS)/include \
		-I$(KERNEL_HEADERS)/arch/$(shell uname -m)/include \
		-I$(KERNEL_HEADERS)/include/uapi \
		-I$(KERNEL_HEADERS)/arch/$(shell uname -m)/include/uapi

LDFLAGS ?= -L$(LIBBPF_DIR)
LDLIBS ?= -l:libbpf.a -lelf -lz

BPF_CFLAGS ?= -I $(LIBBPF_INCLUDE) \
		-I $(IPROUTE_INCLUDE) \
		-I $(ASM_TYPES_INCLUDE) 

ifeq ($(DEBUG),y)
	BPF_EXTRA_FLAGS += -D DEBUG
endif

PERS	?= $(wildcard *.c)

SRCS    = $(PERS)
OBJS    = $(SRCS:.c=.o)

all: llvm-check $(OBJS)

.PHONY: clean $(CLANG) $(LLC)

clean:
	rm -f *.o
	rm -f *.ll
	rm -f *~

llvm-check: $(CLANG) $(LLC)
	@for TOOL in $^ ; do \
		if [ ! $$(command -v $${TOOL} 2>/dev/null) ]; then \
			echo "*** ERROR: Cannot find tool $${TOOL}" ;\
			exit 1; \
		else true; fi; \
	done

%.o: %.c	Makefile
	$(CLANG) \
		-target bpf \
		$(BPF_CFLAGS) \
		-Wall $(BPF_EXTRA_FLAGS) \
		-O2 -c -o $@ $<