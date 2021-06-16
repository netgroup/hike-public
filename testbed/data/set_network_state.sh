#!/bin/bash

PINNED_PATH=/sys/fs/bpf/maps/appcfg/map_app_cfg
BPFTOOL=../tools/bpftool

function __write_le32()
{
	local value="$1"
	local sp="$2"

	printf '%08x' ${value} | \
		sed -E "s/([0-9a-f]{2})([0-9a-f]{2})([0-9a-f]{2})([0-9a-f]{2})/\4${sp}\3${sp}\2${sp}\1/g"

	return 0
}

function __app_cfg_template_update()
{
	local value_hex="$2"
	local key_hex="$1"

	${BPFTOOL} map update			\
	pinned "${PINNED_PATH}"			\
		key hex ${key_hex}		\
		value hex ${value_hex}

	return $?
}

function set_netstate()
{
	local value_hex="$(__write_le32 "$1" ' ')"
	local key_hex="$(__write_le32 "1" ' ')"

	__app_cfg_template_update "${key_hex}" "${value_hex}"

	return $?
}

function set_netstate_critical()
{
	set_netstate 1

	return $?
}

function set_netstate_ok()
{
	set_netstate 0

	return $?
}

function help_and_die()
{
	echo "error: expects 1 argument [ ok | critical ]"
	echo ""
	exit 1
}

if [ $# -ne 1 ]; then
	help_and_die
fi

case "$1" in
	critical)
		set_netstate_critical
		exit $?
		;;
	ok)
		set_netstate_ok
		exit $?
		;;
	*)
		help_and_die
		;;
esac

exit 0
