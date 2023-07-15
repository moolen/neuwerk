import boto3, json

valid_states = ['Pending', 'Pending:Wait', 'Pending:Proceed', 'InService']
leader_tag_key = 'neuwerk:leader'
leader_tag_value = 'true'

autoscaling = boto3.client('autoscaling')
ec2 = boto3.client('ec2')

def lambda_handler(event, context):
    print(f"Received Scaling event: {event}")

    event_detail = event['detail']

    # list all instances currently in the autoscaling group
    response = autoscaling.describe_auto_scaling_groups(AutoScalingGroupNames=[event_detail['AutoScalingGroupName']])
    asg = response['AutoScalingGroups'].pop()
    candidates = []
    all_instance_ids = []

    for instance in asg['Instances']:
        all_instance_ids.append(instance['InstanceId'])
        if instance['LifecycleState'] in valid_states:
            candidates.append(instance['InstanceId'])
            print(f"Instance {instance['InstanceId']} is a candidate for leader.")

    response = ec2.describe_instances(InstanceIds=candidates)
    data = response['Reservations']
    leaders = []
    new_leader = None

    # find all leader instances
    for reservation in data:
        for instance in reservation['Instances']:
            for tag in instance['Tags']:
                if tag['Key'] == leader_tag_key:
                    leaders.append(instance)

    # Get leaders instance ids
    leader_instance_ids = [leader['InstanceId'] for leader in leaders]

    print("leader candidates: ", candidates)
    print("leaders: ", leader_instance_ids)

    # if there's already a leader, don't change anything.
    if len(leaders) == 1:
        print(f"Retaining leader instance {leader_instance_ids[0]}")
        return json.loads(json.dumps(leaders[0], default=str))

    # if there is more than one leader, keep one of them.
    elif len(leaders) > 1:
        new_leader = leader_instance_ids[0]

    # if there are no leaders and the triggering instance is coming online, make it the leader.
    elif "Launching a new EC2 instance:" in event_detail['Description']:
        new_leader = event_detail['EC2InstanceId']

    # Otherwise, just pick a leader.
    else:
        new_leader = candidates[0]

    # flip the tags on all instances.
    response = ec2.delete_tags(Resources=all_instance_ids, Tags=[{'Key': leader_tag_key}])
    if response['ResponseMetadata']['HTTPStatusCode'] != 200:
        print(f"Error deleting tags from non-candidate instances: {response}")
        return

    print(f"Cleared tags on {len(all_instance_ids)} instances")

    params = {
        'Resources': [new_leader],
        'Tags': [{'Key': leader_tag_key, 'Value': leader_tag_value}]
    }

    response = ec2.create_tags(**params)
    if response['ResponseMetadata']['HTTPStatusCode'] != 200:
        print(f"Error creating leader tag on leader instance: {response}")
        return

    print(f"Successfully tagged new leader instance {new_leader}")
    return new_leader