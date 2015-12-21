#!/usr/bin/env python
import os

# AWS Credentials
AWS_ACCESS_KEY = ''
AWS_SECRET_KEY = ''
SSH_KEY_NAME = ''
REGION_NAME = 'eu-central-1'
KEY_FILE = '~/.ssh/id_rsa.pub'
CLOUD_USER = 'ubuntu'
LOCAL_USER = os.environ['USER']

#mysql settings
DB_NAME = "wordpressDB"
DB_USER = "wordpress"
DB_PASSWORD = "wp_password"
DB_ROOT_PASSWORD = "PASSWORDpassword"

#Network settings
VPC_NAME = "wordpress-vpc"
SUBNET_NAME = "wordpress-subnet"
VPC_CIDR = "10.1.1.1/24"

# Reboot wait time
REBOOT_TIME = 180
LAUNCH_TIME = 300

# AWS configuration
AMI_ID = "ami-accff2b1" #ubuntu 14.04-64bit for eu-central-1 region
INSTANCE_NAME = "wordpress-2"
INSTANCE_TYPE = "t2.micro"
SECURITY_GROUP_NAME = "wordpress-sg"
