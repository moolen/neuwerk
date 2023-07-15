#!/bin/bash
set -euo pipefail
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
SSH_KEY=${1}

BASTION_PUBLIC_ADDR=$(terraform output -json | jq -r .bastion_ip.value)
TESTBOX_INTERNAL=$(terraform output -json | jq -r .testbox_ip.value)
NEUWERK_INTERNAL=$(make -s list-instances)

SESSIONNAME="neuwerk"
STARTDIR=$SCRIPT_DIR/../
tmux kill-session -t $SESSIONNAME &> /dev/null || true
tmux new-session -s $SESSIONNAME -c $STARTDIR -n "0" -d

counter=1
for ADDR in $NEUWERK_INTERNAL; do
    tmux new-window -t $SESSIONNAME:$counter -n "${ADDR}" "ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -A -i ${SSH_KEY} -o 'ProxyCommand ssh ec2-user@${BASTION_PUBLIC_ADDR} -W %h:%p' ubuntu@${ADDR}"
    tmux send-keys -t $SESSIONNAME:$counter "sudo sed -i s/127.0.0.53/10.0.0.2/g /etc/resolv.conf" Enter
    sleep 1
    tmux send-keys -t $SESSIONNAME:$counter "sudo systemctl stop systemd-resolved" Enter
    counter=$((counter+1))
done

# configure testbox
tmux new-window -t $SESSIONNAME:$counter -n "testbox:${TESTBOX_INTERNAL}" "ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -A -i ${SSH_KEY} -o 'ProxyCommand ssh ec2-user@${BASTION_PUBLIC_ADDR} -W %h:%p' ec2-user@${TESTBOX_INTERNAL}"

tmux select-window -t $SESSIONNAME:0
tmux attach -t $SESSIONNAME
