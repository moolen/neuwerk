#!/bin/bash
set -euo pipefail
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
SSH_KEY=${1}

BASTION_PUBLIC_ADDR=$(terraform output -json | jq -r .bastion_ip.value)
NEUWERK_INTERNAL=$(make -s list-instances)
TESTBOX_INTERNAL=$(terraform output -json | jq -r .testbox_ip.value)

FILES_TO_COPY="e2e/config.yaml bin/neuwerk"

for INTERNAL_ADDR in $NEUWERK_INTERNAL; do
    # stop neuwerk process from all nodes before we deploy
    ssh -A -i ${SSH_KEY} -o "ProxyCommand ssh ec2-user@${BASTION_PUBLIC_ADDR} -W %h:%p" ubuntu@${INTERNAL_ADDR} 'sudo killall neuwerk' >/dev/null 2>&1 || true
    sleep 2
    echo "uploading to $INTERNAL_ADDR"
    for FILE in $FILES_TO_COPY; do
        scp -A -i "${SSH_KEY}" -o "ProxyCommand ssh ec2-user@${BASTION_PUBLIC_ADDR} -W %h:%p" "${SCRIPT_DIR}/../$FILE" ubuntu@${INTERNAL_ADDR}:/home/ubuntu/$(basename $FILE)
    done
done

scp -A -i "${SSH_KEY}" -o "ProxyCommand ssh ec2-user@${BASTION_PUBLIC_ADDR} -W %h:%p" "${SCRIPT_DIR}/../e2e/e2e.test" ec2-user@${TESTBOX_INTERNAL}:/home/ec2-user/e2e.test
