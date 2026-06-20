# AWS IAM Privilege Escalation Lab

## Overview
A hands-on cloud security lab demonstrating a real world AWS IAM 
privilege escalation technique. A low privilege IAM user exploits 
a misconfigured `iam:CreatePolicyVersion` permission to escalate 
to full administrator access. The entire attack chain is detected 
and investigated using AWS CloudTrail.

## Why This Matters
The `iam:CreatePolicyVersion` privilege escalation path is one of 
the most well documented AWS misconfigurations, referenced in 
Rhino Security Labs' AWS Privilege Escalation research. It has 
been the root cause of real world cloud breaches where an 
attacker with limited access escalated to full account compromise.

## Architecture
| Component | Purpose |
|-----------|---------|
| AWS IAM | Identity and permission management |
| lab-lowpriv-user | Low privilege IAM user — the attacker |
| lab-vulnerable-policy | Misconfigured policy enabling escalation |
| AWS CloudTrail | Logs every API call for detection |
| AWS CLI | Used to simulate the attacker's actions |

## The Vulnerable Permission
The low privilege user was granted this policy:

    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "iam:CreatePolicyVersion",
                    "iam:ListPolicies",
                    "iam:ListPolicyVersions",
                    "iam:GetPolicy",
                    "iam:GetPolicyVersion",
                    "sts:GetCallerIdentity"
                ],
                "Resource": "*"
            }
        ]
    }

`iam:CreatePolicyVersion` allows a user to create a new version of 
ANY policy they can target — including their own — and set it as 
default. This effectively allows self granted privilege escalation.

## Attack Chain

1. Confirm identity — `aws sts get-caller-identity`
2. Enumerate policies — `aws iam list-policies --scope Local`
3. Inspect target policy — `aws iam get-policy`
4. Exploit — `aws iam create-policy-version` with admin permissions 
   set as default version
5. Verify — `aws s3 ls` and `aws iam list-users` now succeed

## Detection
All actions were captured in AWS CloudTrail Event History, 
including the exact source IP, user agent, and the full malicious 
policy document pushed during the escalation.

## Repository Structure
- reports/incident-report-001.md — full investigation report
- evidence/ — CloudTrail screenshots and JSON event logs

## Skills Demonstrated
- AWS IAM policy analysis
- Cloud privilege escalation techniques
- AWS CloudTrail log investigation
- AWS CLI usage for security testing
- Cloud incident reporting
- MITRE ATT&CK Cloud Matrix mapping
