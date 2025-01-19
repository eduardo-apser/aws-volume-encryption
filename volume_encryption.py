#!/usr/bin/python

"""
Overview:
    Iterate through each attached volume and encrypt it for EC2.
Params:
    ID for EC2 instance
    KMS key ID
Conditions:
    Return if volumes are already encrypted with the provided key
"""

import argparse
import sys

import boto3
import botocore
import re


def list_all(client, method, type, **kwargs):
    results = []
    paginator = client.get_paginator(method)
    page_iterator = paginator.paginate(**kwargs)
    for page in page_iterator:
        results += page[type]
    return results


def get_kms_key_arn(session, kms_key_id):
    kms_client = session.client('kms')
    pattern = re.compile(r'^arn:([^:]+):kms:([^:]*):([^:]*):((key|alias)/([^:]+))$')
    match = pattern.match(kms_key_id)
    if match:
        resource_name = match.group(4)
        if resource_name.startswith('alias'):
            alias = list_all(kms_client, 'list_aliases', 'Aliases')
            for alias in alias:
                if alias['AliasName'] == resource_name:
                    return f'arn:{match.group(1)}:kms:{match.group(2)}:{match.group(3)}:key/{alias["TargetKeyId"]}'
        else:
            keys = list_all(kms_client, 'list_keys', 'Keys')
            for key in keys:
                if key['KeyArn'] == kms_key_id:
                    return kms_key_id
    elif kms_key_id.startswith('alias/'):
        alias = list_all(kms_client, 'list_aliases', 'Aliases')
        for alias in alias:
            if alias['AliasName'] == kms_key_id:
                return alias['AliasArn'].replace(kms_key_id, f'key/{alias["TargetKeyId"]}')
    else:
        keys = list_all(kms_client, 'list_keys', 'Keys')
        for key in keys:
            if key['KeyId'] == kms_key_id:
                return key['KeyArn']
    return None


def main(argv):
    parser = argparse.ArgumentParser(description='Encrypts EC2 root volume.')
    parser.add_argument('-i', '--instance', help='Instance to encrypt volume on.', required=True)
    parser.add_argument('-k', '--kms_key_id', help='KMS key', required=True)
    parser.add_argument('-p', '--preserve_volumes', help='Preserve original volumes',
                        required=False, action='store_false')
    args = parser.parse_args()

    """ Set up AWS Session + Client + Resources + Waiters """
    session = boto3.session.Session()

    # Determine KMS key ARN
    kms_key_arn = get_kms_key_arn(session, args.kms_key_id)

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
    """ Get volume and exit if already encrypted with the provided KMS key """

    has_volumes_to_encrypt = False
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

        if volume_encrypted and volume.kms_key_id == kms_key_arn:
            print(
                '**Volume ({}) is already encrypted with KMS key ({})'
                .format(volume.id, kms_key_arn))
            continue
        else:
            has_volumes_to_encrypt = True

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

        if volume.volume_type == 'io1':
            volume_encrypted = ec2.create_volume(
                AvailabilityZone=instance.placement['AvailabilityZone'],
                Encrypted=True,
                Iops=volume.iops,
                KmsKeyId=kms_key_arn,
                SnapshotId=snapshot.id,
                VolumeType=volume.volume_type,
            )
        else:
            volume_encrypted = ec2.create_volume(
                AvailabilityZone=instance.placement['AvailabilityZone'],
                Encrypted=True,
                KmsKeyId=kms_key_arn,
                SnapshotId=snapshot.id,
                VolumeType=volume.volume_type,
            )

        # Add original tags to new volume
        if volume.tags:
            volume_encrypted.create_tags(Tags=[t for t in volume.tags if not t.get(
                'Key').startswith('VolumeEncryptionMetadata:')])

        # Add additional metadata tags to original volumes for traceability
        metadata_tags = [
            {
                'Key': 'VolumeEncryptionMetadata:DeviceName',
                'Value': current_volume_data['DeviceName']
            },
            {
                'Key': 'VolumeEncryptionMetadata:InstanceId',
                'Value': instance_id
            }
        ]
        for t in instance.tags:
            if t['Key'] == 'Name':
                metadata_tags.append({
                    'Key': 'VolumeEncryptionMetadata:InstanceName',
                    'Value': t['Value']
                })
                break
        volume.create_tags(Tags=metadata_tags)

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

    if has_volumes_to_encrypt:
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
            print('---Delete snapshot {}'.format(cleanup['snapshot'].id))
            cleanup['snapshot'].delete()
            if not args.preserve_volumes:
                print('---Skipping deletion of original volume {}'.format(cleanup['volume'].id))
            else:
                print('---Delete original volume {}'.format(cleanup['volume'].id))
                cleanup['volume'].delete()

    print('Encryption finished')


if __name__ == "__main__":
    main(sys.argv[1:])
