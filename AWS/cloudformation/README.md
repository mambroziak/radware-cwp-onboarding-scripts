# Radware Cloud Workload Protection CFT
CloudFormation Template to deploy a role on AWS account to connenct to Radware CWP

# Steps:

## AWS Setup
### [Option 1] One-click CFT Deployment:
[<img src="https://s3.amazonaws.com/cloudformation-examples/cloudformation-launch-stack.png">](https://console.aws.amazon.com/cloudformation/home?region=us-east-1#/stacks/new?stackName=radwareCwpIAMPermissions&templateURL=https://radware-cwp-devops-us-east-1.s3.amazonaws.com/onboarding/cloudformation/Radware-CWP-ReadOnly.yaml)
1. Fill in the parameter fields. Save the **External ID** for a later step.
1. Click Next twice and check "I acknowledge that AWS CloudFormation might create IAM resources." (or use "--capabilities CAPABILITY_IAM" in the AWS CLI.)
1. Click **Create stack**.
1. After the process finished view the **Outputs** tab. Role ARN and External ID will be needed in the next step in the CWP console.

### [Option 2] Manual CFT Deployment:
1. Login to the AWS console, select a region, and navigate to CloudFormation. 
1. Click **Create stack**
1. Under **Specify template**, click **Upload a template file**
1. Click the **Choose file** button and upload the CFT from this repo.
1. Fill in the parameter fields. Save the **External ID** for a later step.
1. Click Next twice and check "I acknowledge that AWS CloudFormation might create IAM resources." (or use "--capabilities CAPABILITY_IAM" in the AWS CLI.)
1. Click **Create stack**.
1. After the process finished view the **Outputs** tab. Role ARN and External ID will be needed in the next step in the CWP console.

## Radware CWP Setup:
1. Log into CWP and then click **Settings > Manage Cloud Accounts** from the menu at the top. 
1. From the top right, click **Add New > AWS Add Accoount**.
1. Click **Continue** twice.
1. Enter an friendly **Account Name**.
1. Copy and paste the **Role ARN** and **External ID** from the CFT output.
1. Click the **Finish Set Up** button.
1. All done!