#!/bin/bash

# This script will parse the console output of all EC2 instances in a region to
# determine if they have been patched against Meltdown (CVE-2017-5754).
# It looks for strings that will only be printed by patched kernels.

# Run this script like so
# $ ./check_meltdown.sh | tee $(date '+%Y-%m-%d').csv

# To only show a subset you can use an aws cli filter like so
# $ ./check_meltdown.sh --filters "Name=tag:Name,Values=prod-*"

QUERY='Reservations[].Instances[].[InstanceId,LaunchTime,PrivateIpAddress,State.Name,Tags[?Key==`Name`] | [0].Value]'
INSTANCES=$(aws ec2 describe-instances --query "${QUERY}" --output text $@ | sed 's/\t/,/g' | tr ' ' '_')
for I in ${INSTANCES}; do
    ID=$(echo "${I}" | cut -d , -f 1)
    LAUNCH_TIME=$(echo "${I}" | cut -d , -f 2)
    IP=$(echo "${I}" | cut -d , -f 3)
    STATE=$(echo "${I}" | cut -d , -f 4)
    NAME=$(echo "${I}" | cut -d , -f 5)
    CONSOLE_OUTPUT=$(aws ec2 get-console-output --instance-id ${ID} --output text | grep -E 'Linux version|isolation|x86/pti|retpoline|Kernel command line')
    # Stolen from https://github.com/speed47/spectre-meltdown-checker
    DMESG_GREP="Kernel/User page tables isolation: enabled"
    DMESG_GREP="${DMESG_GREP}|Kernel page table isolation enabled"
    DMESG_GREP="${DMESG_GREP}|x86/pti: Unmapping kernel while in userspace"
    DMESG_GREP="${DMESG_GREP}|Spectre V2 mitigation: Mitigation: Full generic retpoline"
    KERNEL=$(echo "${CONSOLE_OUTPUT}" | grep 'Linux version' | awk '{print $5}' | tail -n 1)
    if [ -z "${KERNEL}" ]; then
        echo "Couldn't find \"Linux version\", Using Kernel command line" >&2
        KERNEL=$(echo "${CONSOLE_OUTPUT}" | grep 'Kernel command line' | sed 's/.*vmlinuz//' | awk '{print $1}' | tail -n 1)
    fi
    STATUS="VULNERABLE"
    if echo "${CONSOLE_OUTPUT}" | grep -qE "${DMESG_GREP}"; then
        STATUS="PATCHED"
    fi
    echo "${ID},${NAME},${KERNEL},${STATUS},${IP},${STATE},${LAUNCH_TIME}"
done
