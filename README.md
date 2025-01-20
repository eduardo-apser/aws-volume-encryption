# aws-volume-encryption

This repository contains a Python script that automates (re-)encryption of EBS volumes that are attached to an EC2 instance. It is based on [dwbelliston/aws_volume_encryption](https://github.com/dwbelliston/aws_volume_encryption) developed by Dustin Belliston.

Refer to the accompanying blog post [Encrypting EBS Volumes of Amazon EC2 Instances Using Python](https://blog.avangards.io/encrypting-ebs-volumes-of-amazon-ec2-instances-using-python) for more information.

## Prerequisites

1. Install [Python 3.x](https://www.python.org/downloads/).
2. Install the [AWS CLI](http://docs.aws.amazon.com/cli/latest/userguide/installing.html).
3. [Configure your client](http://docs.aws.amazon.com/cli/latest/userguide/cli-chap-getting-started.html).

## Permissions

The AWS principal running the script must have the following permissions:

```json
{
  "Version": "2010-10-10",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ec2:AttachVolume",
        "ec2:CopySnapshot",
        "ec2:CreateSnapshot",
        "ec2:CreateVolume",
        "ec2:DeleteSnapshot",
        "ec2:DeleteVolume",
        "ec2:DescribeInstances",
        "ec2:DescribeSnapshots",
        "ec2:DescribeVolumes",
        "ec2:DetachVolume",
        "ec2:StartInstances",
        "ec2:StopInstances",
        "kms:ListAliases",
        "kms:ListKeys"
      ],
      "Resource": "*"
    }
  ]
}
```

## Usage

```sh
python volume_encryption.py [-h] -i INSTANCE -k KMS_KEY_ID [-p]

Encrypts EBS volumes of an EC2 instance.

options:
  -h, --help            show this help message and exit
  -i INSTANCE, --instance INSTANCE
                        EC2 instance ID
  -k KMS_KEY_ID, --kms_key_id KMS_KEY_ID
                        KMS key
  -p, --preserve_volumes
                        Preserve original volumes
```
