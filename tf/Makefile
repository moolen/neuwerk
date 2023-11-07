plan:
	terraform plan -var-file variables.tfvars

apply:
	terraform apply -var-file variables.tfvars -auto-approve

destroy:
	terraform destroy -var-file variables.tfvars -auto-approve

deploy:
	$(MAKE) -C ../ build
	./deploy.sh $(SSH_KEY_PRIVATE)

forward-metrics:
	ssh -A -L 8888:127.0.0.1:9090 -i "${SSH_KEY_PRIVATE}" -o "ProxyCommand ssh ec2-user@$(shell terraform output -json | jq -r .neuwerk_bastion_ip.value) -W %h:%p" ec2-user@$(shell terraform output -json | jq -r .neuwerk_testbox_ip.value) /bin/sleep 3600

run:
	./run.sh $(SSH_KEY_PRIVATE)

describe-instances:
	@aws ec2 describe-instances  --filters "Name=tag:Name,Values=neuwerk" | jq

list-instances:
	@aws ec2 describe-instances  --filters "Name=tag:Name,Values=neuwerk" | jq -r '.Reservations[].Instances[] | select(.State.Name=="running") | .NetworkInterfaces[] | select(.Description == "egress") | .PrivateIpAddress'

list-instances-mgmt:
	@aws ec2 describe-instances  --filters "Name=tag:Name,Values=neuwerk" | jq -r '.Reservations[].Instances[] | select(.State.Name=="running") | .NetworkInterfaces[] | select(.Description == "management") | .PrivateIpAddress'

list-instances-ingress:
	@aws ec2 describe-instances  --filters "Name=tag:Name,Values=neuwerk" | jq -r '.Reservations[].Instances[] | select(.State.Name=="running") | .NetworkInterfaces[] | select(.Description == "ingress") | .PrivateIpAddress'