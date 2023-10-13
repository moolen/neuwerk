apply:
	terraform apply -var-file variables.tfvars -auto-approve

destroy:
	terraform destroy -var-file variables.tfvars -auto-approve

deploy:
	$(MAKE) -C ../ build
	./deploy.sh $(SSH_KEY_PRIVATE)

run:
	./run.sh $(SSH_KEY_PRIVATE)

describe-instances:
	@aws ec2 describe-instances  --filters "Name=tag:Name,Values=neuwerk" | jq

list-instances:
	@aws ec2 describe-instances  --filters "Name=tag:Name,Values=neuwerk" | jq -r '.Reservations[].Instances[] | select(.State.Name=="running") | .NetworkInterfaces[] | select(.Description == "management") | .PrivateIpAddress'

list-instances-ingress:
	@aws ec2 describe-instances  --filters "Name=tag:Name,Values=neuwerk" | jq -r '.Reservations[].Instances[] | select(.State.Name=="running") | .NetworkInterfaces[] | select(.Description == "ingress") | .PrivateIpAddress'