from scanner import AwsSecurityPostureScanner, format_human_report


class Paginator:
    def __init__(self, pages):
        self.pages = pages

    def paginate(self):
        return self.pages


class Client:
    def __init__(self, data):
        self.data = data

    def list_buckets(self):
        return self.data["list_buckets"]

    def get_bucket_policy_status(self, Bucket):
        return self.data["policy"][Bucket]

    def get_paginator(self, name):
        return Paginator(self.data[name])

    def list_mfa_devices(self, UserName):
        return self.data["mfa"][UserName]


class Session:
    def __init__(self):
        self.s3 = Client(
            {
                "list_buckets": {"Buckets": [{"Name": "public-bucket"}]},
                "policy": {"public-bucket": {"PolicyStatus": {"IsPublic": True}}},
            }
        )
        self.iam = Client(
            {
                "list_users": [{"Users": [{"UserName": "alice"}]}],
                "mfa": {"alice": {"MFADevices": []}},
            }
        )
        self.ec2 = Client(
            {
                "describe_security_groups": [
                    {
                        "SecurityGroups": [
                            {
                                "GroupId": "sg-1",
                                "IpPermissions": [{"IpRanges": [{"CidrIp": "0.0.0.0/0"}]}],
                            }
                        ]
                    }
                ],
                "describe_volumes": [{"Volumes": [{"VolumeId": "vol-1", "Encrypted": False}]}],
            }
        )

    def client(self, service_name, region_name=None):
        return getattr(self, service_name)


def test_scan_and_report():
    report = AwsSecurityPostureScanner(Session(), "us-east-1").scan()

    assert report["summary"]["total_findings"] == 4

    text = format_human_report(report)
    assert "AWS Security Baseline Scanner Report" in text
    assert "public-bucket" in text
