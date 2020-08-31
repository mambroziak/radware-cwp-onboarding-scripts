#!/usr/bin/env python
#
# *******************************************************************************
# Name: cwp_onboard_aws.py
# Version: v1.1
# Description: 
#
# Author: Matt Ambroziak, mambroziak@github
# www.radware.com
#
# PIP Packages required:
#  - requests
#  - boto3
#
# Environment Variables required:
#  - cwp_api_username
#  - cwp_api_password
#
# *******************************************************************************

import json
import time
import os
import sys
import configparser
import argparse
from argparse import RawTextHelpFormatter
import requests
import boto3
from botocore.exceptions import ClientError
import string
from random import *
from time import sleep
from requests.exceptions import HTTPError
from datetime import datetime

api_token = ''
cft_s3_url = ''
mode = ''
OPTIONS = ''

print(
    f'\n:: Radware CWP AWS Onboarding with CFT Deployment Automation :: \nExecution time: {str(datetime.now())} \n')  # Got an error? You need Python 3.6 or later.


def add_aws_account_to_cwp(name, role_arn, external_id):
    arn_parsed = role_arn.split(':')
    account_id = arn_parsed[4]

    url = f'https://api.us-east-1.CWP.radwarecloud.com/api/v1/accounts/account/{account_id}'
    payload = {
        'accountName': name,
        'cloudPlatform': 'AWS',
        'roleArn': role_arn,
        'externalId': external_id
    }

    if OPTIONS.dry_run:
        print('\nDRY-RUN')
        print(f'\nURL: {url}\n\nPAYLOAD: {payload}')
        return True
    else:
        print('\nAdding target AWS account to Radware CWP...')
        resp = http_request('post', url, payload, False)

        if resp.status_code in [200, 201]:
            resp = json.loads(resp.content)
            return True

        elif resp.status_code == 400:
            print('ADD ACCOUNT: Bad request.')
            print(payload)
            return False
        else:
            print('Unknown error when attempting to add AWS account.')
            print(resp)
            return False


def get_aws_accounts_from_cwp():
    url = "https://api.CWP.com/v2/CloudAccounts"
    payload = {}

    print('\nGetting list of AWS accounts already onboarded to CWP...')
    resp = http_request('get', url, payload, False)

    if resp.status_code == 200:
        resp = json.loads(resp.content)
        return resp

    else:
        print('Error when attempting to get list of AWS accounts.')
        print(resp)
        return False


def get_aws_org_parent(aws_org_client, id):
    try:
        parent_resp = aws_org_client.list_parents(
            ChildId=id,
            MaxResults=10
        )['Parents']

        if parent_resp[0]['Type'] == 'ORGANIZATIONAL_UNIT':
            ouresp = aws_org_client.describe_organizational_unit(
                OrganizationalUnitId=parent_resp[0]['Id']
            )['OrganizationalUnit']
            return ouresp
        elif parent_resp[0]['Type'] == 'ROOT':
            return False
    except ClientError as e:
        print(f'Unexpected error: {e}')


def get_cft_stack(aws_cf_client, name):
    try:
        resp = aws_cf_client.describe_stacks(
            StackName=name,
        )['Stacks']
        return resp[0]
    except ClientError as e:
        print(f'Unexpected error: {e}')


def check_cft_stack_exists(aws_cf_client, name):
    try:
        stacks = aws_cf_client.list_stacks()['StackSummaries']
        for stack in stacks:
            if stack['StackStatus'] == 'DELETE_COMPLETE':
                continue
            if name == stack['StackName']:
                return True
    except ClientError as e:
        print(f'Unexpected error: {e}')


def create_cft_stack(aws_cf_client, name, cft_url, external_id):
    try:
        resp = aws_cf_client.create_stack(
            StackName=name,
            TemplateURL=cft_url,
            Parameters=[
                {
                    'ParameterKey': 'ExternalId',
                    'ParameterValue': external_id
                }
            ],
            Capabilities=['CAPABILITY_IAM'],
        )
        return resp
    except ClientError as e:
        print(f'Unexpected error: {e}')
        return False


def mode_crossaccount_onboard(aws_sts_client):
    assume_role_arn = 'arn:aws:iam::' + OPTIONS.account_number + ':role/' + OPTIONS.role_name  # Build role ARN of target account being onboarded to assume into
    print(f'\nAssuming Role into target account using ARN: {assume_role_arn}')

    sts_resp = aws_sts_client.assume_role(
        RoleArn=assume_role_arn,
        RoleSessionName='DeploycwpCFTSession',
        DurationSeconds=1800
    )
    aws_cf_client = boto3.client('cloudformation',
                                 aws_access_key_id=sts_resp['Credentials']['AccessKeyId'],
                                 aws_secret_access_key=sts_resp['Credentials']['SecretAccessKey'],
                                 aws_session_token=sts_resp['Credentials']['SessionToken'],
                                 region_name=OPTIONS.region_name
                                 )

    process_account(aws_cf_client, OPTIONS.account_name)


def mode_organizations_onboard(aws_org_client, aws_sts_client, aws_cf_client):
    # function to print stats upon completion
    def _print_stats(discovered, successes, failures):
        print(
            f'\n\nOnboarding Statistics:\n  Discovered: {discovered}\n  Successes: {successes}\n  Failures: {failures}\n  Skipped: {(discovered - failures - successes)}')

    # Get AWS accounts from Orgs and iterate through the pages to create a list
    org_accounts_raw = aws_org_client.list_accounts(
        MaxResults=20)  # Get first page of accounts, unknown if there are more pages yet
    org_accounts_pruned = []
    next_token = False
    count_successes = 0
    count_failures = 0

    for account in org_accounts_raw['Accounts']:
        org_accounts_pruned.extend([{'id': account['Id'], 'name': account['Name']}])

    if 'NextToken' in org_accounts_raw:  # More pages of accounts to process
        next_token = True

    while next_token:
        print('Fetching next page of accounts...')
        org_accounts_raw = aws_org_client.list_accounts(NextToken=org_accounts_raw['NextToken'], MaxResults=20)
        for account in org_accounts_raw['Accounts']:
            org_accounts_pruned.extend([{'id': account['Id'], 'name': account['Name']}])
        if 'NextToken' in org_accounts_raw:
            next_token = True
        else:
            next_token = False  # testing False, was True
            print('\nEnd of cloud acounts list.')
            break

    # Get AWS accounts from CWP and iterate through to create a list    
    cwp_aws_accounts_raw = get_aws_accounts_from_cwp()
    cwp_aws_accounts_pruned = {''}
    for account in cwp_aws_accounts_raw:
        cwp_aws_accounts_pruned.add(account['externalAccountNumber'])

    unprotected_account_list = [d for d in org_accounts_pruned if (
        d['id']) not in cwp_aws_accounts_pruned]  # create list of AWS accounts not found in CWP

    if len(unprotected_account_list) == 0:
        print("No unprotected accounts found.")
        exit(1)
    else:
        print(f'\nFound the following unprotected AWS Accounts: ')
        for account in unprotected_account_list:
            print(f'  {account["id"]} | {account["name"]}')

    caller_account_number = boto3.client('sts', region_name=OPTIONS.region_name).get_caller_identity()[
        'Account']  # Identify caller AWS account which needs to be processed without STS assume 

    for account in unprotected_account_list:
        print(f'\n*** Initiating onboarding for: {account["id"]} | {account["name"]}')

        if account['id'] == caller_account_number:
            cwp_cloud_account_id = process_account(aws_cf_client, account['name'])
        else:
            assume_role_arn = 'arn:aws:iam::' + account[
                'id'] + ':role/' + OPTIONS.role_name  # Build role ARN of target account being onboarded to assume into
            print(f'\nAssuming Role into target account using ARN: {assume_role_arn}')

            sts_resp = aws_sts_client.assume_role(
                role_arn=assume_role_arn,
                RoleSessionName='DeployCwpCftSession',
                DurationSeconds=1800
            )
            aws_cf_client = boto3.client('cloudformation',
                                         aws_access_key_id=sts_resp['Credentials']['AccessKeyId'],
                                         aws_secret_access_key=sts_resp['Credentials']['SecretAccessKey'],
                                         aws_session_token=sts_resp['Credentials']['SessionToken'],
                                         region_name=OPTIONS.region_name
                                         )

            cwp_cloud_account_id = process_account(aws_cf_client, account['name'])

        if (not cwp_cloud_account_id) and not OPTIONS.ignore_failures:
            count_failures += 1
            print(f'\nError when attempting to onboard AWS account to CWP. Exiting...')
            _print_stats(len(unprotected_account_list), count_successes, count_failures)
            exit(1)
        elif cwp_cloud_account_id:
            count_successes += 1

    _print_stats(len(unprotected_account_list), count_successes, count_failures)


def process_account(aws_cf_client, aws_account_name):
    # Check if the CFT Stack exists from a previous run
    cwp_stack = 'RadwareCWP-ReadOnly-Policy-Automated'
    if check_cft_stack_exists(aws_cf_client, cwp_stack):
        print('\nStack exists.  Perhaps this script has already been run?')
        return False
    else:
        print('\nCreating CloudFormation Stack...')

    print('\nProvisioning the CloudFormation stack in AWS...')
    external_id = ''.join(choice(string.ascii_letters + string.digits) for _ in range(24))
    stack_created = create_cft_stack(aws_cf_client, cwp_stack, cft_s3_url, external_id)

    # CHECK CFT STATUS
    t = 0
    while t < 20:
        t += 1
        stack = get_cft_stack(aws_cf_client, cwp_stack)
        if stack['StackStatus'] not in ['CREATE_IN_PROGRESS', 'CREATE_COMPLETE']:
            print(f'Something went wrong during CFT stack deployment: {stack["StackStatus"]}')
            return False
        elif stack['StackStatus'] == 'CREATE_COMPLETE':
            print('Success! Stack created.')
            break
        else:
            print(f'... Try {t}/20: {stack["StackStatus"]}')
            sleep(15)

            # Get CFT Stack info to pull the Role ARN
    cft_stack = get_cft_stack(aws_cf_client, cwp_stack)
    role_arn = ''
    for output in cft_stack['Outputs']:
        if output['OutputKey'] == 'RoleARNID':
            role_arn = output['OutputValue']

    # Add the AWS account to CWP
    cwp_account_added = add_aws_account_to_cwp(aws_account_name, role_arn, external_id)
    print(f'Added: {role_arn.split(":")[4]} | {aws_account_name} | {cwp_account_added}')
    return cwp_account_added


def get_api_token(username, password):
    url = 'https://sas.CWP.radwarecloud.com/sas/login'
    payload = {"username": username, "password": password}

    api_session = http_request(request_type='post', url=url, payload=payload, token=None, silent=False)
    api_session = json.loads(api_session.content)

    return api_session['token']


def http_request(request_type, url, payload, token, silent):
    # request_type = post/delete/get
    request_type = request_type.lower()
    # silent = True/False

    if token:
        headers = {'Content-Type': 'application/json',
                   'Authorization': f'BEARER {token}'}
    else:
        print("INFO: No API token tendered for HTTP request.")
        headers = {'Content-Type': 'application/json'}

    resp = ''
    try:
        if request_type.lower() == 'post':
            resp = requests.post(url, json=payload, headers=headers)
        elif request_type.lower() == 'delete':
            resp = requests.delete(url, json=payload, headers=headers)
        elif request_type.lower() == 'get':
            resp = requests.get(url, json=payload, headers=headers)
        else:
            print('Request type not supported.')
            return False

        resp.raise_for_status()
    except HTTPError as http_err:
        print(f'HTTP error occurred: {http_err}')
    except Exception as err:
        print(f'Other error occurred: {err}')
    else:
        if not silent:
            print('Success!')

    return resp


def main(argv=None):
    global api_token, cft_s3_url, mode, OPTIONS

    # handle arguments
    if argv is None:
        argv = sys.argv[2:]

    example_text = f'\nHelp with modes:\n {sys.argv[0]} local --help\n {sys.argv[0]} cross-account --help\n {sys.argv[0]} organizations --help\nExamples:\n {sys.argv[0]} local --name "AWS DEV" --region us-east-1\n {sys.argv[0]} cross-account --account 987654321012 --name "AWS DEV" --role MyRoleName --region us-east-1\n {sys.argv[0]} organizations --role MyRoleName --region us-east-1 --ignore-failures'

    parser = argparse.ArgumentParser(epilog=example_text, formatter_class=RawTextHelpFormatter)
    parser._action_groups.pop()
    required = parser.add_argument_group('required arguments')
    optional = parser.add_argument_group('optional arguments')

    optional.add_argument('--region', dest='region_name', default='us-east-1',
                          help='AWS Region Name for CWP CFT deployment. Default: us-east-1')
    optional.add_argument('--dry-run', dest='dry_run', default=False,
                          help='Dry-run (read-only mode for testing)', action='store_true')

    if len(sys.argv) == 1:
        parser.print_help()
        exit(1)

    if sys.argv[1]:
        mode = sys.argv[1].lower()
        print(f'\nMode: {mode}')
        if mode not in ['local', 'cross-account', 'organizations']:
            print('ERROR: Invalid run mode.\n')
            parser.print_help()
            exit(1)
    else:
        parser.print_help()
        exit(1)

    if mode == 'local':
        required.add_argument('--name', dest='account_name',
                              help='Cloud account friendly name in quotes (e.g. "AWS PROD")', required=True)
    elif mode == 'cross-account':
        required.add_argument('--account', dest='account_number', help='Cloud account number (e.g. 987654321012)',
                              required=True)
        required.add_argument('--name', dest='account_name',
                              help='Cloud account friendly name in quotes (e.g. "AWS PROD")', required=True)
        required.add_argument('--role', dest='role_name',
                              help='AWS cross-account access role for Assume-Role. (e.g. MyRoleName)', required=True)
    elif mode == 'organizations':
        required.add_argument('--role', dest='role_name',
                              help='AWS cross-account access role for Assume-Role. (e.g. MyRoleName)', required=True)
        optional.add_argument('--ignore-failures', dest='ignore_failures', default=False,
                              help='Ignore onboarding failures and continue.', action='store_true')
    elif mode == '-h' or mode == '--help':
        parser.print_help()
        exit(1)

    OPTIONS = parser.parse_args(argv)

    # load config file
    config = configparser.ConfigParser()
    config.read("./cwp_onboard_aws.conf")

    # Get CWP API credentials from env variables
    if not os.environ.get('cwp_api_username') or not os.environ.get('cwp_api_password'):
        print('\nERROR: Radware CWP API credentials not found in environment variables.')
        exit(1)
    else:
        token = get_api_token(username=os.environ.get('cwp_api_username'), password=os.environ.get('cwp_api_password'))
        print(f"My Token: {token[0:15]}...")

    # Get AWS creds for the client. Region is needed for CFT deployment location.
    print('\nCreating AWS service clients...\n')
    aws_cf_client = boto3.client('cloudformation', region_name=OPTIONS.region_name)
    try:  # Check for successful authentication
        aws_cf_client.list_stacks()
    except ClientError as e:
        print(f'ERROR: Unable to authenticate to AWS using environment variables or IAM role.')
        exit(1)

    if mode == 'cross-account':
        aws_sts_client = boto3.client('sts', region_name=OPTIONS.region_name)
    elif mode == 'organizations':
        aws_org_client = boto3.client('organizations', region_name=OPTIONS.region_name)
        aws_sts_client = boto3.client('sts', region_name=OPTIONS.region_name)

    cft_s3_url = config.get('aws', 'cft_s3_url')

    if OPTIONS.dry_run:
        print('\n*** DRY RUN ENABLED ***')

    if mode == 'local' and OPTIONS.account_name and OPTIONS.region_name:
        process_account(aws_cf_client, OPTIONS.account_name)
    elif mode == 'cross-account' and OPTIONS.account_number and OPTIONS.account_name and OPTIONS.role_name and OPTIONS.region_name:
        mode_crossaccount_onboard(aws_sts_client)
    elif mode == 'organizations' and OPTIONS.role_name and OPTIONS.region_name:
        if OPTIONS.ignore_ou:  # Ignore OU processing flag detected
            print('\nIgnore Organizational Units flag is set to True. All AWS accounts will be placed in root.')
        mode_organizations_onboard(aws_org_client, aws_sts_client, aws_cf_client)
    else:
        parser.print_help()
        exit(1)
    return 0


if __name__ == '__main__': main()
