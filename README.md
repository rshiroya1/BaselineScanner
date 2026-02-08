# aws-security-posture-scanner

Lightweight Python tool that scans an AWS account for common security baseline issues.

## Checks

- Public S3 buckets
- IAM users without MFA
- Security groups open to `0.0.0.0/0`
- Unencrypted EBS volumes

## Output

- `scan_report.json`
- `scan_report.txt`

## Quick start

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python scanner.py --region us-east-1
```

Optional profile:

```bash
python scanner.py --profile my-audit-profile --region us-east-1
```

Custom output paths:

```bash
python scanner.py --json-out reports/latest.json --text-out reports/latest.txt
```

## Notes

- AWS credentials must be configured (profile, env vars, or IAM role).
- Scanner needs read permissions for S3, IAM, and EC2.
