#!/usr/bin/python

"""
Overview:
    Iterate through each attached volume and encrypt it for EC2.
Params:
    ID for EC2 instance
    Customer Master Key (CMK) (optional)
Conditions:
    Return if volume already encrypted
"""

import argparse
import sys

import boto3
import botocore


def main(argv):
    parser = argparse.ArgumentParser(description='Encrypts EC2 root volume.')
    parser.add_argument('-i', '--instance',
                        help='Instance to encrypt volume on.', required=True)
    parser.add_argument('-key', '--customer_master_key',
                        help='Customer master key', required=False)
    args = parser.parse_args()

    """ Set up AWS Session + Client + Resources + Waiters """
    session = boto3.session.Session()

    # Get CMK
    customer_master_key = args.customer_master_key

    client = session.client('ec2')
    ec2 = session.resource('ec2')

    waiter_instance_exists = client.get_waiter('instance_exists')
    waiter_instance_stopped = client.get_waiter('instance_stopped')
    waiter_instance_running = client.get_waiter('instance_running')
    waiter_snapshot_complete = client.get_waiter('snapshot_completed')
    waiter_volume_available = client.get_waiter('volume_available')

    """ Check instance exists """
    instance_id = args.instance
    print('---Checking instance ({})'.format(instance_id))
    instance = ec2.Instance(instance_id)

    try:
        waiter_instance_exists.wait(
            InstanceIds=[
                instance_id,
            ]
        )
    except botocore.exceptions.WaiterError as e:
        sys.exit('ERROR: {}'.format(e))

    all_mappings = []

    block_device_mappings = instance.block_device_mappings

    for device_mapping in block_device_mappings:
        original_mappings = {
            'DeleteOnTermination': device_mapping['Ebs']['DeleteOnTermination'],
            'DeviceName': device_mapping['DeviceName'],
            'VolumeId': device_mapping['Ebs']['VolumeId'],
        }
        all_mappings.append(original_mappings)

    volume_data = []

    print('---Preparing instance')
    """ Get volume and exit if already encrypted """
    volumes = [v for v in instance.volumes.all()]
    for volume in volumes:
        volume_encrypted = volume.encrypted

        current_volume_data = {}
        for mapping in all_mappings:
            if mapping['VolumeId'] == volume.volume_id:
                current_volume_data = {
                    'DeleteOnTermination': mapping['DeleteOnTermination'],
                    'DeviceName': mapping['DeviceName'],
                    'volume': volume,
                }

        if volume_encrypted:
            sys.exit(
                '**Volume ({}) is already encrypted'
                .format(volume.id))

        """ Step 1: Prepare instance """

        # Exit if instance is pending, shutting-down, or terminated
        instance_exit_states = [0, 32, 48]
        if instance.state['Code'] in instance_exit_states:
            sys.exit(
                'ERROR: Instance is {} please make sure this instance is active.'
                .format(instance.state['Name'])
            )

        # Validate successful shutdown if it is running or stopping
        if instance.state['Code'] == 16:
            instance.stop()

        # Set the max_attempts for this waiter (default 40)
        waiter_instance_stopped.config.max_attempts = 80

        try:
            waiter_instance_stopped.wait(
                InstanceIds=[
                    instance_id,
                ]
            )
        except botocore.exceptions.WaiterError as e:
            sys.exit('ERROR: {}'.format(e))

        """ Step 2: Take snapshot of volume """
        print('---Create snapshot of volume ({})'.format(volume.id))
        snapshot = ec2.create_snapshot(
            Description='Snapshot of volume ({})'.format(volume.id),
            VolumeId=volume.id,
        )

        waiter_snapshot_complete.config.max_attempts = 240

        try:
            waiter_snapshot_complete.wait(
                SnapshotIds=[
                    snapshot.id,
                ]
            )
        except botocore.exceptions.WaiterError as e:
            snapshot.delete()
            sys.exit('ERROR: {}'.format(e))

        """ Step 3: Create encrypted volume """
        print('---Create encrypted volume from snapshot')

        if customer_master_key:
            if volume.volume_type == 'io1':
                volume_encrypted = ec2.create_volume(
                    AvailabilityZone=instance.placement['AvailabilityZone'],
                    Encrypted=True,
                    Iops=volume.iops,
                    KmsKeyId=customer_master_key,
                    SnapshotId=snapshot.id,
                    VolumeType=volume.volume_type,
                )
            else:
                volume_encrypted = ec2.create_volume(
                    AvailabilityZone=instance.placement['AvailabilityZone'],
                    Encrypted=True,
                    KmsKeyId=customer_master_key,
                    SnapshotId=snapshot.id,
                    VolumeType=volume.volume_type,
                )
        else:
            if volume.volume_type == 'io1':
                volume_encrypted = ec2.create_volume(
                    AvailabilityZone=instance.placement['AvailabilityZone'],
                    Encrypted=True,
                    Iops=volume.iops,
                    SnapshotId=snapshot.id,
                    VolumeType=volume.volume_type,
                )
            else:
                volume_encrypted = ec2.create_volume(
                    AvailabilityZone=instance.placement['AvailabilityZone'],
                    Encrypted=True,
                    SnapshotId=snapshot.id,
                    VolumeType=volume.volume_type,
                )

        # Add original tags to new volume
        if volume.tags:
            volume_encrypted.create_tags(Tags=volume.tags)

        """ Step 4: Detach current volume """
        print('---Detach volume {}'.format(volume.id))
        instance.detach_volume(
            Device=current_volume_data['DeviceName'],
            VolumeId=volume.id,
        )

        """ Step 5: Attach new encrypted volume """
        print('---Attach volume {}'.format(volume_encrypted.id))
        try:
            waiter_volume_available.wait(
                VolumeIds=[
                    volume_encrypted.id,
                ],
            )
        except botocore.exceptions.WaiterError as e:
            snapshot.delete()
            volume_encrypted.delete()
            sys.exit('ERROR: {}'.format(e))

        instance.attach_volume(
            Device=current_volume_data['DeviceName'],
            VolumeId=volume_encrypted.id,
        )

        current_volume_data['snapshot'] = snapshot
        volume_data.append(current_volume_data)

    for bdm in volume_data:
        # Modify instance attributes
        instance.modify_attribute(
            BlockDeviceMappings=[
                {
                    'DeviceName': bdm['DeviceName'],
                    'Ebs': {
                        'DeleteOnTermination':
                        bdm['DeleteOnTermination'],
                    },
                },
            ],
        )
    """ Step 6: Start instance """
    print('---Start instance')
    instance.start()
    try:
        waiter_instance_running.wait(
            InstanceIds=[
                instance_id,
            ]
        )
    except botocore.exceptions.WaiterError as e:
        sys.exit('ERROR: {}'.format(e))

    """ Step 7: Clean up """
    print('---Clean up resources')
    for cleanup in volume_data:
        print('---Remove snapshot {}'.format(cleanup['snapshot'].id))
        cleanup['snapshot'].delete()
        print('---Remove original volume {}'.format(cleanup['volume'].id))
        cleanup['volume'].delete()

    print('Encryption finished')


if __name__ == "__main__":
    main(sys.argv[1:])
