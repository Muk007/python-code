import boto3
import logging
import os
import json
import urllib3
import datetime
import re

e = datetime.datetime.now()

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def lambda_handler(event, context):
    target_connection = boto3.client('sts',region_name='us-west-2', endpoint_url='https://sts.us-west-2.amazonaws.com')
    target_account = target_connection.assume_role(
        RoleArn=os.environ['INSTANCE_QUERY_ROLE'],
        RoleSessionName="target_account_session"
    )

    operations_connection = boto3.client('sts',region_name='us-west-2', endpoint_url='https://sts.us-west-2.amazonaws.com')
    dns_account = operations_connection.assume_role(
        RoleArn=os.environ['DNS_QUERY_ROLE'],
        RoleSessionName="dns_account_session"
    )
    tACCESS_KEY = target_account['Credentials']['AccessKeyId']
    tSECRET_KEY = target_account['Credentials']['SecretAccessKey']
    tSESSION_TOKEN = target_account['Credentials']['SessionToken']

    dACCESS_KEY = dns_account['Credentials']['AccessKeyId']
    dSECRET_KEY = dns_account['Credentials']['SecretAccessKey']
    dSESSION_TOKEN = dns_account['Credentials']['SessionToken']

    ec2 = boto3.client(
        "ec2", 
        region_name='us-west-2',
        aws_access_key_id=tACCESS_KEY,
        aws_secret_access_key=tSECRET_KEY,
        aws_session_token=tSESSION_TOKEN
    )

    r53 = boto3.client(
        "route53",
        region_name='us-west-2',
        aws_access_key_id=dACCESS_KEY,
        aws_secret_access_key=dSECRET_KEY,
        aws_session_token=dSESSION_TOKEN
    )

    all_regions = ec2.describe_regions()['Regions']
    inventory = {}
    for region in all_regions:
        ec2_region = boto3.client(
            "ec2",
            region_name=region['RegionName'],
            aws_access_key_id=tACCESS_KEY,
            aws_secret_access_key=tSECRET_KEY,
            aws_session_token=tSESSION_TOKEN
        )
        lb = boto3.client(
            "elb",
            region_name=region['RegionName'],
            aws_access_key_id=tACCESS_KEY,
            aws_secret_access_key=tSECRET_KEY,
            aws_session_token=tSESSION_TOKEN
        )

        ccn_nodes = ec2_region.describe_instances(Filters=[{'Name':'tag:Name','Values':['*-ccn-*']}, {'Name': 'instance-state-name', 'Values': ['running']}])
        for nodes in ccn_nodes['Reservations']:
            for instance in nodes['Instances']:
                if region['RegionName'] not in inventory.keys():
                    inventory[region['RegionName']] = []
                instance_dict = find_node_names(instance,ec2_region,lb,r53)
                inventory[region['RegionName']].append(instance_dict)
        logger.info("Instance ID are collected from region: {}".format(region['RegionName']))
    upload_to_s3(inventory)

def find_node_names(instance,ec2_region,lb,r53):
    instance_dict   = {}
    instance_dict['instance_id'] = instance['InstanceId']
    instance_name   = ""
    for tags in instance['Tags']:
        if tags['Key'] == 'Name':
            instance_name=tags['Value']
            break
    logger.info("Instance ID of {} is: {}".format(instance_name, instance['InstanceId']))
    instance_dict['instance_name'] = instance_name
    uxn_nodes_result = ec2_region.describe_instances(Filters=[{'Name':'tag:Name','Values':[instance_name.replace("ccn","uxn")]}, {'Name': 'instance-state-name', 'Values': ['running']}])
    uxn_name = ""
    for uxn_nodes in uxn_nodes_result['Reservations']:
        for uxn_node in uxn_nodes['Instances']:
            instance_dict['uxn_ip'] = uxn_node['PrivateIpAddress']
            for uxn_tag in uxn_node['Tags']:
                if uxn_tag['Key'] == 'Name':
                    uxn_name=uxn_tag['Value']
                    logger.info("UXN Node name: {}".format(uxn_name))
                    break
    if uxn_name:
        instance_dict['lb_dns_name']    = find_lb(lb,uxn_name)
        instance_dict['subdomain']      = find_subdomain (r53, instance_dict['lb_dns_name'])
    return instance_dict

def upload_to_s3(inventory_data):
    s3 = boto3.resource('s3')
    s3object = s3.Object(os.environ['BUCKET_NAME'], 'ansible-inventory.json')
    s3object.put(
        Body=(bytes(json.dumps(inventory_data, indent=4).encode('UTF-8')))
    )

def find_lb(lb,uxn_name):
    lookup_text = ""
    try:
        lookup_text = uxn_name.replace('tf','elb')
        elbs = lb.describe_load_balancers(LoadBalancerNames=[lookup_text])
        if elbs['LoadBalancerDescriptions'] and len(elbs['LoadBalancerDescriptions'])>0:
            return elbs['LoadBalancerDescriptions'][0]['DNSName']
    except Exception as err:
        logger.error("Exception looking up {}: {}".format(lookup_text, err))
    return None

def find_subdomain(r53, lb_dns_name):
    subdomain = ""
    try:
        zones = r53.list_hosted_zones_by_name(DNSName='mistnet.io.')
        mistnet_zone = zones['HostedZones'][0]['Id']
        if mistnet_zone:
            record_sets = r53.list_resource_record_sets(HostedZoneId=mistnet_zone,MaxItems='500')
            for record in record_sets['ResourceRecordSets']:
                if record['Type'] == 'A' and 'AliasTarget' in record.keys() and record['AliasTarget'] and record['AliasTarget']['DNSName'] == lb_dns_name+'.':
                    url = record['Name']
                    subdomain = url.replace('.mistnet.io.', '')
                    break
        return subdomain
    except Exception as err:
        logger.error("Exception looking up {}: {}".format(lb_dns_name, err))
    return None
