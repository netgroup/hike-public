
BUILD ?= $(addprefix $(shell pwd)/,build)
SRC_DIR ?= $(shell pwd)

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

# cmd line cannot override any of those vars below
# ================================================
# Root HIKe Directory (i.e.: src HIKe's directory)
override __HIKE_DIR := $(abspath $(HIKE_DIR))

override __OUTPUT := $(abspath $(BUILD))
override __SRC_DIR := $(abspath $(SRC_DIR))
override __EBPF_SRC := $(PROG)
override __HIKE_CHAIN_SRC := $(CHAIN)
# ------------------------------------------------

.PHONY: all prog chain

all:
	$(error You cannot invoke "all" target)

# TODO: fix the name of mandatory vars removing the "__" prefix

prog:
	$(call check_defined, __HIKE_DIR)
	$(call check_defined, PROG)
	$(call check_dir, __HIKE_DIR, $(__HIKE_DIR))
	cd $(__HIKE_DIR) && \
		$(MAKE) prog SRC_DIR=$(__SRC_DIR) EBPF_SRC=$(__EBPF_SRC) \
			OUTPUT=$(__OUTPUT)

chain:
	$(call check_defined, __HIKE_DIR)
	$(call check_defined, CHAIN)
	$(call check_dir, __HIKE_DIR, $(__HIKE_DIR))
	cd $(__HIKE_DIR) && \
		$(MAKE) chain SRC_DIR=$(__SRC_DIR)			\
			HIKE_CHAIN_SRC=$(__HIKE_CHAIN_SRC)		\
			OUTPUT=$(__OUTPUT)

.PHONY: clean
clean:
	rm -rf $(__OUTPUT)

