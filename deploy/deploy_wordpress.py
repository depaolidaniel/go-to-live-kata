#!/usr/bin/env python

# Standard imports
import csv
import datetime
import os.path
import os
import re
import sys
import time
import argparse

# Fabric and fabtools imports
from fabric.api import run, sudo, settings, env, cd, put, execute
from fabric.colors import red, green, yellow
from fabric.contrib.files import exists, upload_template
from fabric.operations import reboot, prompt, get
from fabtools.system import get_sysctl, set_sysctl
from fabric.exceptions import NetworkError

# Boto imports
import boto
import boto.ec2
import boto.vpc
import boto.rds
from boto.ec2.connection import EC2Connection
from boto.exception import BotoServerError
from boto.exception import EC2ResponseError
from boto.ec2.blockdevicemapping import EBSBlockDeviceType, BlockDeviceMapping
from StringIO import StringIO

#import variable file
from variable import *

'''
Function for wordpress deployment
'''
def deploy_mysql():
    try:
        sudo("apt-get update")
        sudo("debconf-set-selections <<< \"mysql-server mysql-server/root_password password {}\"".format(DB_ROOT_PASSWORD))
        sudo("debconf-set-selections <<< \"mysql-server mysql-server/root_password_again password {}\"".format(DB_ROOT_PASSWORD))
        sudo("apt-get --yes install mysql-server")
        run("mysql --user=root --password={} -e \"CREATE DATABASE {}\"".format(DB_ROOT_PASSWORD, DB_NAME))
        run("mysql --user=root --password={} -e \"CREATE USER '{}'@'localhost' IDENTIFIED BY '{}'\"".format(DB_ROOT_PASSWORD, DB_USER, DB_PASSWORD))
        run("mysql --user=root --password={} -e \"CREATE USER '{}'@'%' IDENTIFIED BY '{}'\"".format(DB_ROOT_PASSWORD, DB_USER, DB_PASSWORD))
        run("mysql --user=root --password={} -e \"GRANT ALL PRIVILEGES ON {}.* TO '{}'@'localhost' WITH GRANT OPTION\"".format(DB_ROOT_PASSWORD, DB_NAME, DB_USER))
        run("mysql --user=root --password={} -e \"GRANT ALL PRIVILEGES ON {}.* TO '{}'@'%' WITH GRANT OPTION\"".format(DB_ROOT_PASSWORD, DB_NAME, DB_USER))
        run("mysql --user=root --password={} -e \"FLUSH PRIVILEGES\"".format(DB_ROOT_PASSWORD))
        return True
    except Exception:
        return False

def deploy_wordpress():
    try:
        sudo("apt-get update")
        sudo("apt-get --yes install apache2 php5 libapache2-mod-php5 php5-gd libssh2-php php5-mcrypt php5-mysql unzip")
        run("wget https://wordpress.org/latest.zip")
        sudo("unzip -q latest.zip -d /var/www/html/")
        sudo("chown -R www-data.www-data /var/www/html/wordpress")
        sudo("chmod -R 755 /var/www/html/wordpress")
        sudo("mkdir -p /var/www/html/wordpress/wp-content/uploads")
        sudo("chown -R :www-data /var/www/html/wordpress/wp-content/uploads")
        sudo("cp /var/www/html/wordpress/wp-config-sample.php /var/www/html/wordpress/wp-config.php")
        sudo("sed -e \"s/define('DB_NAME'.*$/define('DB_NAME', '{}');/\" -i /var/www/html/wordpress/wp-config.php".format(DB_NAME))
        sudo("sed -e \"s/define('DB_USER'.*$/define('DB_USER', '{}');/\" -i /var/www/html/wordpress/wp-config.php".format(DB_USER))
        sudo("sed -e \"s/define('DB_PASSWORD'.*$/define('DB_PASSWORD', '{}');/\" -i /var/www/html/wordpress/wp-config.php".format(DB_PASSWORD))
        sudo("service apache2 restart")
        return True
    except Exception:
        return False

def launch_instance(subnet=None, security_group=None):
    '''
    Launch an ubuntu instance.
    '''
    #Check if an instance is already present:
    instance = None
    for i in ec2_connection.get_all_instances():
        if "Name" in i.instances[0].tags and i.instances[0].state == "running":
            if  i.instances[0].tags["Name"] == INSTANCE_NAME:
                print(green("Instance already present. Use it"))
                instance = i.instances[0]
                break

    if instance == None:

        instance_key_name = SSH_KEY_NAME

        interface = boto.ec2.networkinterface.NetworkInterfaceSpecification(subnet_id=subnet.id, associate_public_ip_address=True)
        interfaces = boto.ec2.networkinterface.NetworkInterfaceCollection(interface)
        reservation = ec2_connection.run_instances(AMI_ID, 
                           instance_type=INSTANCE_TYPE, key_name=SSH_KEY_NAME, network_interfaces=interfaces) #, subnet_id=subnet.id)

        instance = reservation.instances[0]
        instance.modify_attribute('groupSet',[security_group.id])
        print(green("Launching instance on reservation {}.".format(instance, reservation)))
      
        print(yellow('Waiting for instance to start...'))
        set_tags = False
        while instance.state == u'pending':
            # Try to set tags.
            if set_tags == False:
                try:
                    ec2_connection.create_tags([instance.id], {"Name": INSTANCE_NAME})
                    set_tags = True
                    print(green("Instance {} tagged.".format(instance)))
                except EC2ResponseError, e:
                    print(red("Tagging failed; sleeping, updating instance, and trying again."))

            time.sleep(10)
            instance.update()

        if instance.state != u'running':
            raise RuntimeError("Instance {} state is {}.".format(instance, instance.state))
            return None

        #Set environment
        bootstrap(instance.public_dns_name)

        '''
        Wait for the instance to be available
        using simple command output for checking
        '''
        print(green('Waiting host coming up...'))
        ready = False
        while not ready:
            try:
                ssh_ret = run('ifconfig', timeout=2)
                ready = True
            except Exception:
                ready = False
        print(green('Host ready!'))

    #Waiting that sources.list is changed.
    print(yellow('Wait {} seconds.').format(LAUNCH_TIME))
    time.sleep(LAUNCH_TIME)
    return instance

def create_vpc_and_subnet():
    vpc_conn = boto.vpc.connect_to_region(REGION_NAME, aws_access_key_id=AWS_ACCESS_KEY, aws_secret_access_key=AWS_SECRET_KEY)
    virtual_private_cloud = None
    for vpc in vpc_conn.get_all_vpcs():
        if "Name" in vpc.tags:
            if vpc.tags["Name"] == VPC_NAME:
                print(yellow('VPC already present. Use it.'))
                virtual_private_cloud = vpc
                break
    if virtual_private_cloud == None:
        print(green('Creating new VPC'))
        virtual_private_cloud = vpc_conn.create_vpc(VPC_CIDR)
        virtual_private_cloud.add_tag("Name", VPC_NAME)
        vpc_conn.modify_vpc_attribute(virtual_private_cloud.id, enable_dns_support=True)
        vpc_conn.modify_vpc_attribute(virtual_private_cloud.id, enable_dns_hostnames=True)

    subnet = None
    for sb in vpc_conn.get_all_subnets():
        if "Name" in sb.tags:
            if sb.tags["Name"] == SUBNET_NAME:
                print(yellow('Subnet already present. Use it.'))
                subnet = sb
                break
    if subnet == None:
        print(green('Creating new SUBNET'))
        gateway = vpc_conn.create_internet_gateway()
        vpc_conn.attach_internet_gateway(gateway.id, virtual_private_cloud.id)
        route_table = vpc_conn.create_route_table(virtual_private_cloud.id)
        subnet = vpc_conn.create_subnet(virtual_private_cloud.id, VPC_CIDR)
        vpc_conn.associate_route_table(route_table.id, subnet.id)
        route = vpc_conn.create_route(route_table.id, '0.0.0.0/0', gateway.id)
        subnet.add_tag("Name", SUBNET_NAME)

    return virtual_private_cloud, subnet

def create_security_group(ec2_connection, vpc):
    '''
    Create a single security group.
    '''
    # Check existing security groups for match.
    security_group_list = ec2_connection.get_all_security_groups()
    for security_group in security_group_list:
        if security_group.name == SECURITY_GROUP_NAME:
            print(yellow('Security group already present. Use it.'))
            return security_group

    # First, create group.
    print(green('Creating new SECURITY GROUP'))
    security_group = ec2_connection.create_security_group(SECURITY_GROUP_NAME, "Wordpress test", vpc_id=vpc.id)

    # Add ssh and OEM.
    security_group.authorize('tcp', 22, 22, '0.0.0.0/0')
    security_group.authorize('tcp', 80, 80, '0.0.0.0/0')
    security_group.authorize('tcp', 443, 443, '0.0.0.0/0')
    security_group.authorize('tcp', 3306, 3306, VPC_CIDR)

    return security_group

def bootstrap(host_name, user_name=CLOUD_USER, key_filename=KEY_FILE):
    env.host_string = host_name
    env.user = CLOUD_USER
    env.key_filename = KEY_FILE

def parser():
    parser = argparse.ArgumentParser(description='Deploy wordpress on aws script')
    parser.add_argument("--access-key", action='store',
        help="Aws user access key", required=True)
    parser.add_argument("--secret-key", action='store',
        help="Aws secret key", required=True)
    parser.add_argument("--ssh-key", action='store',
        help="Aws ssh key name", required=True)
    return parser.parse_args()

#Main function
if __name__ == "__main__":

    args = parser()
    AWS_ACCESS_KEY = args.access_key
    AWS_SECRET_KEY = args.secret_key
    SSH_KEY_NAME = args.ssh_key

    # Create EC2 connection
    try:
        ec2_connection = boto.ec2.connect_to_region(REGION_NAME, aws_access_key_id=AWS_ACCESS_KEY, aws_secret_access_key=AWS_SECRET_KEY)
    except Exception as e:
        print "Error:", e
        print "Cannot continue to wordpress deployment"
        sys.exit(1)

    # Check if key-pair-name exist
    key_exist=False
    for i in ec2_connection.get_all_key_pairs():
        if i.name == SSH_KEY_NAME:
            key_exist = True
            break
    if not key_exist:
        print "Error: key", SSH_KEY_NAME, "not present."
        print "Available key:", ",".join([item.name for item in list(ec2_connection.get_all_key_pairs())])
        sys.exit(2)

    vpc, subnet = create_vpc_and_subnet()

    security_group = create_security_group(ec2_connection, vpc=vpc)

    instance = launch_instance(subnet=subnet, security_group = security_group)
    if not instance:
        print "No instance launched"
        sys.exit(3)

    bootstrap(instance.public_dns_name)

    deploy_mysql = deploy_mysql()
    deploy_wordpress = deploy_wordpress()

    if deploy_wordpress and deploy_mysql:
        print green("Wordpress ready at http://{}/wordpress".format(instance.public_dns_name))
    else:
        print red("Wordpress not ready")