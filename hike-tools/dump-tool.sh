#!/bin/bash

if [ "$#" -ne 5 ]; then
	echo -e "error: missing args.\n\nExpected args: <obj> <sec> <chain_id> <pinmap> <output>"
	echo ""
	echo "chain_id := { [0-9]+ | auto }"
	echo ""
	exit 1
fi

OBJ="$(realpath "$1")"
SEC="$2"
CHAIN_ID="$3"
PINMAP="$4"
OUTPUT_FILE="$5"

if [ ! -f "${OBJ}" ]; then
	echo "error: file object \""${OBJ}"\" does not exist"
	exit 1
fi

# =========================
# --- DO NOT EDIT BELOW ---
# =========================

readonly SCRIPT_DIR="$(cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd)"
HIKE_VM_CORE="${SCRIPT_DIR}/../src/hike_vm.h"

readonly JQ="$(realpath "${SCRIPT_DIR}/../tools/jq-linux64")"

# Try to build the hikevm binary so that we can extract BTF info from that
readonly BUILD_DIR="${SCRIPT_DIR}/objs"
readonly HIKEVM_BTF_JSON="${BUILD_DIR}/hikevm.bpf.json"
readonly MAKE_HIKEVM="$(realpath "${SCRIPT_DIR}/../external/Makefile")"
readonly NUMCPUS=`grep -c '^processor' /proc/cpuinfo`

# Compile the hikevm binary
make -f ../external/Makefile -j${NUMCPUS} \
	prog "HIKE_DIR=../src/" "SRC_DIR=../src/" "PROG=hikevm.bpf.c" \
	"BUILD=${BUILD_DIR}" || exit $?

if [ ! -f ${HIKEVM_BTF_JSON} ]; then
	echo "error: cannot locate the ${HIKEVM_BTF_JSON}"
	exit 1
fi

# --------------------------------------------------------------------------- #
# get the ID of the json element which describes the array containing the
# text instructions of a HIKe Chain.
___BUFF='.types[] | '
___BUFF+='select(.kind=="STRUCT" and .name=="hike_chain") | '
___BUFF+='.members[] | '
___BUFF+='select(.name=="insns") | '
___BUFF+='.type_id'

ELEM_ID="$(jq "${___BUFF}" "${HIKEVM_BTF_JSON}")"; RC=$?
if [ ${RC} -ne 0 ]; then
	echo "error: an error occurred during btf.json analysis"
	exit ${RC}
fi

___BUFF='.types[] | '
___BUFF+="select(.kind==\"ARRAY\" and .id==${ELEM_ID}) | "
___BUFF+='.nr_elems'

HIKE_CHAIN_NINSN_MAX="$(jq "${___BUFF}" "${HIKEVM_BTF_JSON}")"; RC=$?
if [ ${RC} -ne 0 ]; then
	echo "error: an error occurred during btf.json analysis"
	exit ${RC}
fi
# --------------------------------------------------------------------------- #
# get the offset of the HIKe Chain text section
___BUFF='.types[] | '
___BUFF+='select(.kind=="STRUCT" and .name=="hike_chain") | '
___BUFF+='.members[] | '
___BUFF+='select(.name=="___sec_text___") | '
___BUFF+='.bits_offset'

HIKE_CHAIN_SEC_TEXT_OFFBITS="$(jq "${___BUFF}" "${HIKEVM_BTF_JSON}")"; RC=$?
if [ ${RC} -ne 0 ]; then
	echo "error: an error occurred during btf.json analysis"
	exit ${RC}
fi
# --------------------------------------------------------------------------- #

HIKE_CHAIN_HEADER_LEN=$((HIKE_CHAIN_SEC_TEXT_OFFBITS/8))

TMP_PATH="/tmp"

TMP="${TMP_PATH}/insns.bin"
TMP_HEADER="${TMP_PATH}/hdr.bin"
OUT="${TMP_PATH}/chain.bin"
OUT_ASCII="${TMP_PATH}/$(mktemp --dry-run tmp.XXXXXXXX)"

function __clean()
{
	rm "${TMP}" "${TMP_HEADER}" "${OUT}" "${OUT_ASCII}" 2>/dev/null
}

function __write_le16()
{
	local value="$1"
	local sp="$2"

	printf '%04x' ${value} | \
		sed -E "s/([0-9a-f]{2})([0-9a-f]{2})/\2${sp}\1/g"

	return 0
}

function write_le16()
{
	local out="$1"
	local value="$2"
	local off="$3"

	__write_le16 ${value} '' | \
		xxd -r -p - | dd of="${out}" bs=1 count=2 seek=${off} conv=notrunc

	return 0
}

function __write_le32()
{
	local value="$1"
	local sp="$2"

	printf '%08x' ${value} | \
		sed -E "s/([0-9a-f]{2})([0-9a-f]{2})([0-9a-f]{2})([0-9a-f]{2})/\4${sp}\3${sp}\2${sp}\1/g"

	return 0
}

function write_le32()
{
	local out="$1"
	local value="$2"
	local off="$3"

	__write_le32 ${value} '' | \
		xxd -r -p - | dd of="${out}" bs=1 count=4 seek=${off} conv=notrunc

	return 0
}

function extract_chain_id()
{
	local chain_id
	local sec="$1"

	if [ -z "${sec}" ]; then
		return 1
	fi

	chain_id="$(echo "${sec}" \
		| sed -En 's/^__sec_hike_chain_([0-9]{1,})$/\1/gp')"
	if [ -z "${chain_id}" ]; then
		return 1
	fi

	echo ${chain_id}
	return 0
}

# fill the header with zeros for the whole length of the chain header
# (i.e.: chain id, ninsn, registers, etc)
dd if=/dev/zero bs=1 count=${HIKE_CHAIN_HEADER_LEN} of="${TMP_HEADER}"

if [ "${CHAIN_ID}" == "auto" ]; then
	CHAIN_ID="$(extract_chain_id "${SEC}")"
	if [ $? -ne 0 ]; then
		echo "error: cannot get chain id from section \"${SEC}\""

		__clean
		exit 1
	fi
fi

# write chain id
write_le32 "${TMP_HEADER}" ${CHAIN_ID} 0

llvm-objcopy-12 --only-section="${SEC}" "${OBJ}" -O binary "${TMP}"

SIZE="$(stat --printf="%s" "${TMP}")"

if [ ${SIZE} -eq 0 ]; then
	echo "error: cannot extract ${SEC} from binary"

	__clean
	exit 1
fi

NINSN=$((SIZE / 8))
PAD=$((HIKE_CHAIN_NINSN_MAX * 8 - SIZE))

# write the number of instructions
write_le16 "${TMP_HEADER}" ${NINSN} 4

if [ ${PAD} -ge 0 ]; then
	# Let's pad the binary containing the instructions up to 32 insns in total
	dd if=/dev/zero bs=1 count=${PAD} >> "${TMP}"
else
	echo "error: too many instructions for the HIKe Chain"

	__clean
	exit 1
fi

# merge the header of the chain with the instructions
cat "${TMP_HEADER}" "${TMP}" > "${OUT}"

# generate the bpftool command with the whole chain in ASCII:
#  - we allow the user to inspect the code
#  - we allow the user to load the chain directly using bash
CHAIN_ID_ASCII="$(__write_le32 ${CHAIN_ID} ' ')"
CHAIN_INSN_ASCII="$(xxd -g 1 -c 8 "${OUT}" | \
	awk '{ print $2" "$3" "$4" "$5" "$6" "$7" "$8" "$9" \\"}')"

cat <<-EOF >"${OUT_ASCII}"
	#!/bin/bash

	bpftool map update					\\
		pinned ${PINMAP}				\\
		key hex 					\\
			${CHAIN_ID_ASCII}			\\
		value hex					\\
			${CHAIN_INSN_ASCII}
EOF

mv -v "${OUT_ASCII}" "${OUTPUT_FILE}"
chmod a+x "${OUTPUT_FILE}"

__clean

exit 0
