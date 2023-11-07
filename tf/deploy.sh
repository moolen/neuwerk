#!/bin/bash
set -euo pipefail
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

SSH_KEY=${1}
SSH_ARGS="-o StrictHostKeyChecking=no -A -i ${SSH_KEY}"

NEUWERK_BASTION_PUBLIC_ADDR=$(terraform output -json | jq -r .neuwerk_bastion_ip.value)
NEUWERK_INTERNAL=$(make -s list-instances)
NEUWERK_TESTBOX_INTERNAL=$(terraform output -json | jq -r .neuwerk_testbox_ip.value)

FILES_TO_COPY="e2e/config.yaml bin/neuwerk"

for INTERNAL_ADDR in $NEUWERK_INTERNAL; do
    # stop neuwerk process from all nodes before we deploy
    ssh $SSH_ARGS -o "ProxyCommand ssh ec2-user@${NEUWERK_BASTION_PUBLIC_ADDR} -W %h:%p" ubuntu@${INTERNAL_ADDR} 'sudo killall neuwerk' >/dev/null 2>&1 || true
    sleep 2
    echo "uploading to $INTERNAL_ADDR"
    for FILE in $FILES_TO_COPY; do
        scp $SSH_ARGS -o "ProxyCommand ssh ec2-user@${NEUWERK_BASTION_PUBLIC_ADDR} -W %h:%p" "${SCRIPT_DIR}/../$FILE" ubuntu@${INTERNAL_ADDR}:/home/ubuntu/$(basename $FILE)
    done
done

scp $SSH_ARGS -o "ProxyCommand ssh ec2-user@${NEUWERK_BASTION_PUBLIC_ADDR} -W %h:%p" "${SCRIPT_DIR}/../e2e/e2e.test" ec2-user@${NEUWERK_TESTBOX_INTERNAL}:/home/ec2-user/e2e.test

# deploy monitoring
scp $SSH_ARGS -o "ProxyCommand ssh ec2-user@${NEUWERK_BASTION_PUBLIC_ADDR} -W %h:%p" "${SCRIPT_DIR}/setup-prometheus.sh" ec2-user@${NEUWERK_TESTBOX_INTERNAL}:/home/ec2-user/setup-prometheus.sh
ssh $SSH_ARGS -o "ProxyCommand ssh ec2-user@${NEUWERK_BASTION_PUBLIC_ADDR} -W %h:%p" ec2-user@${NEUWERK_TESTBOX_INTERNAL} "./setup-prometheus.sh '${NEUWERK_INTERNAL}'"
