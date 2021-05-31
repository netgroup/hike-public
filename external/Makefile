
BUILD ?= build

#######################
## DO NOT EDIT BELOW ##
#######################

# Check that given variables are set and all have non-empty values,
# die with an error otherwise.
#
# Params:
#   1. Variable name(s) to test.
#   2. (optional) Error message to print.
check_defined = \
    $(strip $(foreach 1,$1, \
        $(call __check_defined,$1,$(strip $(value 2)))))
__check_defined = \
    $(if $(value $1),, \
      $(error Undefined $1$(if $2, ($2))))

# Let's avoid any duplication of the code :-)
define check_dir
	@if [ ! -d $(2) ]; then 			\
		echo "Invalid $(1) \"$(2)\"";		\
		exit 2; 				\
	fi
endef

HIKE_DIR_ABS := $(abspath $(HIKE_DIR))
PWD := $(abspath $(shell pwd))

export OUTPUT := $(abspath $(shell pwd)/$(BUILD))
export SRC_DIR := $(PWD)
export EBPF_SRC := $(PROG)
export HIKE_CHAIN_SRC := $(CHAIN)

.PHONY: all prog chain

all:
	$(error You cannot invoke "all" target)

prog:
	$(call check_defined, HIKE_DIR)
	$(call check_defined, PROG)
	$(call check_dir, HIKE_DIR_ABS, $(HIKE_DIR_ABS))
	cd $(HIKE_DIR_ABS) && $(MAKE) $@

chain:
	$(call check_defined, HIKE_DIR)
	$(call check_defined, CHAIN)
	$(call check_dir, HIKE_DIR_ABS, $(HIKE_DIR_ABS))
	cd $(HIKE_DIR_ABS) && $(MAKE) $@

.PHONY: clean
clean:
	rm -rf $(OUTPUT)

