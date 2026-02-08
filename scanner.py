#!/usr/bin/env python3
"""AWS Cloud Security Baseline Scanner."""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from typing import Any


class AwsSecurityPostureScanner:
    def __init__(self, session: Any, region: str):
        self.region = region
        self.s3 = session.client("s3")
        self.iam = session.client("iam")
        self.ec2 = session.client("ec2", region_name=region)

    def scan(self) -> dict[str, Any]:
        findings = (
            self.check_public_s3_buckets()
            + self.check_iam_users_without_mfa()
            + self.check_open_security_groups()
            + self.check_unencrypted_ebs_volumes()
        )

        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "region": self.region,
            "summary": {
                "total_findings": len(findings),
                "errors": [],
            },
            "findings": findings,
        }

    def check_public_s3_buckets(self) -> list[dict[str, str]]:
        findings: list[dict[str, str]] = []
        for bucket in self.s3.list_buckets().get("Buckets", []):
            name = bucket["Name"]
            status = self.s3.get_bucket_policy_status(Bucket=name)
            if status.get("PolicyStatus", {}).get("IsPublic"):
                findings.append(
                    {
                        "control": "Public S3 bucket",
                        "resource": f"s3://{name}",
                        "details": "Bucket policy allows public access.",
                    }
                )
        return findings

    def check_iam_users_without_mfa(self) -> list[dict[str, str]]:
        findings: list[dict[str, str]] = []
        for page in self.iam.get_paginator("list_users").paginate():
            for user in page.get("Users", []):
                username = user["UserName"]
                devices = self.iam.list_mfa_devices(UserName=username).get("MFADevices", [])
                if not devices:
                    findings.append(
                        {
                            "control": "IAM user without MFA",
                            "resource": f"iam:user/{username}",
                            "details": "No MFA device assigned.",
                        }
                    )
        return findings

    def check_open_security_groups(self) -> list[dict[str, str]]:
        findings: list[dict[str, str]] = []
        for page in self.ec2.get_paginator("describe_security_groups").paginate():
            for sg in page.get("SecurityGroups", []):
                group_id = sg.get("GroupId", "unknown")
                for perm in sg.get("IpPermissions", []):
                    if any(ip.get("CidrIp") == "0.0.0.0/0" for ip in perm.get("IpRanges", [])):
                        findings.append(
                            {
                                "control": "Security group open to world",
                                "resource": f"ec2:security-group/{group_id}",
                                "details": "Ingress rule allows traffic from 0.0.0.0/0.",
                            }
                        )
        return findings

    def check_unencrypted_ebs_volumes(self) -> list[dict[str, str]]:
        findings: list[dict[str, str]] = []
        for page in self.ec2.get_paginator("describe_volumes").paginate():
            for volume in page.get("Volumes", []):
                if not volume.get("Encrypted", False):
                    findings.append(
                        {
                            "control": "Unencrypted EBS volume",
                            "resource": f"ec2:volume/{volume.get('VolumeId', 'unknown')}",
                            "details": "EBS encryption is disabled.",
                        }
                    )
        return findings


def format_human_report(report: dict[str, Any]) -> str:
    lines = [
        "AWS Security Baseline Scanner Report",
        "=" * 36,
        f"Generated at: {report['generated_at']}",
        f"Region: {report['region']}",
        f"Total findings: {report['summary']['total_findings']}",
        "",
        "Findings",
        "--------",
    ]

    if not report["findings"]:
        lines.append("No risky baseline misconfigurations detected.")
    else:
        for finding in report["findings"]:
            lines.append(f"- {finding['control']} ({finding['resource']})")
    return "\n".join(lines)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Scan AWS account for baseline risks.")
    parser.add_argument("--profile", default=None, help="AWS profile name")
    parser.add_argument("--region", default="us-east-1", help="AWS region")
    parser.add_argument("--json-out", default="scan_report.json", help="JSON report path")
    parser.add_argument("--text-out", default="scan_report.txt", help="Text report path")
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    import boto3

    session = boto3.Session(profile_name=args.profile) if args.profile else boto3.Session()
    report = AwsSecurityPostureScanner(session=session, region=args.region).scan()

    with open(args.json_out, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    text_report = format_human_report(report)
    with open(args.text_out, "w", encoding="utf-8") as f:
        f.write(text_report)

    print(text_report)


if __name__ == "__main__":
    main()
