terraform {
  experiments = [variable_validation]
}

variable "external_id" {
  type = string
  description = "Enter External ID for Radware CWP Role (mininum length: 8) (e.g. a1b2c3d4e5f6)"
  
  validation {
    condition     = length(var.external_id) >= 8
	error_message = "The external_id value must be at least 8 characters in length."
  }
}

variable "s3_bucket_flowlogs" {
  type = string
  description = "Enter VPC FlowLogs S3 bucket name, prefix optional. (e.g. mybucketname/myprefix)"
  
  validation {
    condition     = substr(var.s3_bucket_flowlogs, (length(var.s3_bucket_flowlogs))-1, 1) != "/" && length(var.s3_bucket_flowlogs) >= 3
	error_message = "The s3_bucket_flowlogs value cannot have a trailing '/' character or length less than 3."
  }
}

variable "s3_bucket_cloudtrail" {
  type = string
  description = "Enter the CloudTrail logs S3 bucket name, prefix optional. (e.g. mybucketname/myprefix)"
  
  validation {
    condition     = substr(var.s3_bucket_cloudtrail, (length(var.s3_bucket_cloudtrail))-1, 1) != "/" && length(var.s3_bucket_cloudtrail) >= 3
	error_message = "The s3_bucket_cloudtrail value cannot have a trailing '/' character or length less than 3."
  }
}

#Create the role and setup the trust policy
resource "aws_iam_role" "cwp" {
  name               = "RadwareCWP_Role"
  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::342443945406:root"
      },
      "Action": "sts:AssumeRole",
      "Condition": {
        "StringEquals": {
          "sts:ExternalId": "${var.external_id}"
        }
      }
    }
  ]
}
EOF

}

#Create the ReadOnly policy
resource "aws_iam_policy" "readonly-policy" {
  name        = "RadwareCWPReadOnlyAccess"
  description = ""
  policy      = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": [
                "s3:ListBucket"
            ],
            "Resource": [
                "arn:aws:s3:::${var.s3_bucket_flowlogs}/",
                "arn:aws:s3:::${var.s3_bucket_flowlogs}/*",
                "arn:aws:s3:::${var.s3_bucket_cloudtrail}/",
                "arn:aws:s3:::${var.s3_bucket_cloudtrail}/*"
            ],
            "Effect": "Allow",
            "Sid": "ListBuckets"
        },
        {
            "Action": [
                "s3:Get*"
            ],
            "Resource": [
                "arn:aws:s3:::${var.s3_bucket_flowlogs}/AWSLogs/",
                "arn:aws:s3:::${var.s3_bucket_flowlogs}/AWSLogs/*",
                "arn:aws:s3:::${var.s3_bucket_cloudtrail}/AWSLogs/",
                "arn:aws:s3:::${var.s3_bucket_cloudtrail}/AWSLogs/*"
            ],
            "Effect": "Allow",
            "Sid": "ReadLogs"
        },
		{
            "Action": [
                "logs:GetLogEvents",
                "logs:FilterLogEvents",
                "s3:ListBucket",
                "sns:ListSubscriptions",
                "elasticfilesystem:DescribeTags",
                "dynamodb:ListTagsOfResource",
                "wafv2:ListResourcesForWebACL",
                "wafv2:ListWebACLs",
                "waf-regional:ListResourcesForWebACL"
            ],
            "Resource": "*",
            "Effect": "Allow",
            "Sid": "RadwareCWPReadOnlyAccess"
        }
    ]
}
EOF

}

#Attach 3 policies to the cross-account role
resource "aws_iam_policy_attachment" "attach-cwp-readonly-policy" {
  name       = "attach-readonlypolicy"
  roles      = [aws_iam_role.cwp.name]
  policy_arn = aws_iam_policy.readonly-policy.arn
}

resource "aws_iam_role_policy_attachment" "attach-security-audit-policy" {
  role       = aws_iam_role.cwp.name
  policy_arn = "arn:aws:iam::aws:policy/SecurityAudit"
}

resource "aws_iam_role_policy_attachment" "attach-inspector-readonly-policy" {
  role       = aws_iam_role.cwp.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonInspectorReadOnlyAccess"
}

#Output the role ARN
output "Role_ARN" {
  value = aws_iam_role.cwp.arn
}