#! /usr/bin/env python
# -*- coding: UTF-8 -*-
import os
import sys
import json
import hvac
import boto3
import logging
import urllib2
import argparse
import threading
import ConfigParser

parser = argparse.ArgumentParser(description='Bouncer is a a AWS security group updater, based on github web-hooks CIDRs.')
parser.add_argument('-c','--config', help='Loads configuration', required=True)
args = vars(parser.parse_args())

if args['config']:
    config = ConfigParser.ConfigParser()
    config.read(args['config'])

    vault_server =  config.get('global', 'vault_server')
    vault_token  =  config.get('global', 'vault_token')
    vault_secret =  config.get('global', 'vault_secret_path') 
    vault_client =  hvac.Client(url=vault_server, token=vault_token)
    vault_config =  vault_client.read(vault_secret)['data']

    DEFAULT_PORT     = vault_config['default_port']
    AWS_ACCESS_KEY   = vault_config['aws_access_key_id']
    AWS_SECRET_KEY   = vault_config['aws_secret_access_key']
    SECURITY_GROUP   = vault_config['aws_sg_id']
    REFRESH_INTERVAL = vault_config['refresh_interval']
   
    logger = logging.getLogger(__name__)
    handler = logging.StreamHandler(sys.stdout)
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler) 
    logger.setLevel(logging.INFO)
    logger.info('Starting Bouncer') 

    def github_cidrs():
        response = urllib2.urlopen("https://api.github.com/meta")
        data = json.load(response)
        return data['hooks']

    def ingress_template(cidr):
        return {'IpProtocol': 'tcp', 'FromPort': int(DEFAULT_PORT), 'ToPort': int(DEFAULT_PORT), 'IpRanges': [{'CidrIp': cidr, 'Description': 'Managed by Bouncer'}]}
        
    def build_rules(cidrs):
        data = []
        for cidr in cidrs:
            ingress = ingress_template(cidr)
            data.append(ingress)
        return data

    def update_sg_rules():
        threading.Timer(float(REFRESH_INTERVAL), update_sg_rules).start()
        session = boto3.session.Session(aws_access_key_id=AWS_ACCESS_KEY, aws_secret_access_key=AWS_SECRET_KEY)
        client = session.client('ec2', region_name='us-east-1')

        current_rules = client.describe_security_groups(GroupIds=[SECURITY_GROUP])['SecurityGroups'][0]['IpPermissions']

        current_cidrs_list = []
        for rule in current_rules:
            for ip in rule['IpRanges']:
                cidr = ip['CidrIp']
                current_cidrs_list.append(cidr)

        cidrs_diff = set(github_cidrs()) - set(current_cidrs_list)

        if cidrs_diff:
            client.authorize_security_group_ingress(GroupId=SECURITY_GROUP,IpPermissions=build_rules(list(cidrs_diff)))
            client.revoke_security_group_ingress(GroupId=SECURITY_GROUP,IpPermissions=build_rules(list(set(current_cidrs_list) - set(github_cidrs()))))
            logger.info('The security rules (ingresses) from the security {} group has been changed'.format(SECURITY_GROUP))
        else:
            logger.info('The security rules (ingresses) from the security group has been not changed')

    def main():
        update_sg_rules()

if __name__ == "__main__":
    main()
