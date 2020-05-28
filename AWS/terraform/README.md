# Radware Cloud Workload Protection Terraform Template
This terraform template will create the roles and policies needed to allow Radware CWP to protect an AWS Account. This template is run for each account being protected.

# Steps:

## Terraform Setup:
1. Run `terraform plan` and validate the results.
1. To deploy the template, run `terraform apply`
1. Enter an External ID and record it for the next section.
1. Enter the S3 Bucket names for CloudTrail Logs
1. Enter the S3 Bucket name for VPC FlowLogs.
1. In the Outputs, find the "Role_ARN" and record it for the next section.

Example:
```BASH
terraform apply \
-var='external_id=abc123abc123' \
-var='s3_bucket_cloudtrail=myCloudTrailS3BucketName' \
-var='s3_bucket_flowlogs=myFlowLogsS3BucketName'
```

## Radware CWP Setup:
1. Log into CWP and then click **Settings > Manage Cloud Accounts** from the menu at the top. 
1. From the top right, click **Add New > AWS Add Accoount**.
1. Click **Continue** twice.
1. Enter an friendly **Account Name**.
1. Copy and paste the **Role ARN** and **External ID** from the Terraform output.
1. Click the **Finish Set Up** button.
1. All done!