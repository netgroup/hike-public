#!/bin/bash


export SCRIPT_DIR="$(cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd)"
export DMPTOOL="${SCRIPT_DIR}/dump-tool.sh"

export OBJDMP=llvm-objdump

export TMP_PATH="/tmp"
export TMPFILE="${TMP_PATH}/$(mktemp --dry-run tmp.XXXXXXXX)"

function __compile()
{
	local obj="$1"
	local map="$2"
	local out="$3"
	local sechdr

	if [ ! -f "${obj}" ]; then
		echo "error: file object \"$obj\" not found"
		echo ""
		exit 1
	fi

	:> "${out}"
	if [ $? -ne 0 ]; then
		echo "error: cannot open file \"${out}\""
		echo ""
		exit 1
	fi

	for sechdr in $(${OBJDMP} --section-headers "${obj}" | \
			awk '$2 ~ /__sec_hike_chain_[0-9]+/ { print $2 }'); do

		:> "${TMPFILE}"

		${DMPTOOL} "${obj}" "${sechdr}" auto "${map}" "${TMPFILE}" &>/dev/null
		if [ $? -ne 0 ]; then
			echo "error: cannot dump the section \"${sechdr}\""
			echo ""
			exit 1
		fi

		 #a blank line at the end of the script
		echo "" >> "${TMPFILE}"

		dd if="${TMPFILE}" bs=512 conv=notrunc \
			oflag=append of="${out}" &>/dev/null
	done

	rm "${TMPFILE}" 2>/dev/null

	return 0
}

if [ "$#" -ne 3 ]; then
	echo -e "error missing args.\n\nExpected args: <obj> <pinmap> <output>"
	echo ""
	exit 1
fi

__compile "$1" "$2" "$3"
exit $?
