"""
AWS Service module for interacting with AWS RDS and SSM.
Uses boto3 for AWS operations. Supports multiple AWS accounts.
"""

import boto3
from typing import List, Dict, Optional, Any
from botocore.exceptions import ClientError, NoCredentialsError

from .config import get_aws_config


def get_boto3_session(aws_account_alias: str = None) -> boto3.Session:
    """Create a boto3 session for a specific AWS account."""
    aws_config = get_aws_config(alias=aws_account_alias)
    if not aws_config:
        raise ValueError(
            f"AWS account '{aws_account_alias or 'default'}' not found. "
            f"Configure it in Admin > AWS Accounts."
        )

    return boto3.Session(
        aws_access_key_id=aws_config.access_key_id or None,
        aws_secret_access_key=aws_config.secret_access_key or None,
        region_name=aws_config.region or 'us-east-1',
    )


def get_rds_client(aws_account_alias: str = None):
    """Get RDS client for a specific AWS account."""
    session = get_boto3_session(aws_account_alias)
    return session.client('rds')


def get_ssm_client(aws_account_alias: str = None):
    """Get SSM client for a specific AWS account."""
    session = get_boto3_session(aws_account_alias)
    return session.client('ssm')


def get_ec2_client(aws_account_alias: str = None):
    """Get EC2 client for a specific AWS account."""
    session = get_boto3_session(aws_account_alias)
    return session.client('ec2')


def test_aws_connection(aws_account_alias: str = None) -> Dict[str, Any]:
    """Test AWS connection and return status."""
    try:
        session = get_boto3_session(aws_account_alias)
        sts = session.client('sts')
        identity = sts.get_caller_identity()
        return {
            "success": True,
            "account": identity.get('Account'),
            "arn": identity.get('Arn'),
            "user_id": identity.get('UserId'),
        }
    except NoCredentialsError:
        return {
            "success": False,
            "error": "No AWS credentials configured",
        }
    except ValueError as e:
        return {
            "success": False,
            "error": str(e),
        }
    except ClientError as e:
        return {
            "success": False,
            "error": str(e),
        }
    except Exception as e:
        return {
            "success": False,
            "error": f"Unexpected error: {str(e)}",
        }


def list_aurora_clusters(aws_account_alias: str = None) -> List[Dict[str, Any]]:
    """List all Aurora PostgreSQL clusters."""
    try:
        rds = get_rds_client(aws_account_alias)
        response = rds.describe_db_clusters()
        clusters = []

        for cluster in response.get('DBClusters', []):
            if 'aurora-postgresql' in cluster.get('Engine', ''):
                clusters.append({
                    "id": cluster.get('DBClusterIdentifier'),
                    "endpoint": cluster.get('Endpoint'),
                    "reader_endpoint": cluster.get('ReaderEndpoint'),
                    "port": cluster.get('Port'),
                    "status": cluster.get('Status'),
                    "engine": cluster.get('Engine'),
                    "engine_version": cluster.get('EngineVersion'),
                })

        return clusters
    except Exception as e:
        return []


def list_aurora_instances(aws_account_alias: str = None) -> List[Dict[str, Any]]:
    """List all Aurora PostgreSQL instances."""
    try:
        rds = get_rds_client(aws_account_alias)
        response = rds.describe_db_instances()
        instances = []

        for instance in response.get('DBInstances', []):
            if 'aurora-postgresql' in instance.get('Engine', ''):
                endpoint_info = instance.get('Endpoint', {})
                instances.append({
                    "id": instance.get('DBInstanceIdentifier'),
                    "cluster_id": instance.get('DBClusterIdentifier'),
                    "endpoint": endpoint_info.get('Address'),
                    "port": endpoint_info.get('Port'),
                    "status": instance.get('DBInstanceStatus'),
                    "engine": instance.get('Engine'),
                    "engine_version": instance.get('EngineVersion'),
                    "instance_class": instance.get('DBInstanceClass'),
                    "is_writer": instance.get('DBClusterIdentifier') is not None,
                })

        return instances
    except Exception as e:
        return []


def get_cluster_endpoints(cluster_id: str, aws_account_alias: str = None) -> Dict[str, Any]:
    """Get endpoints for a specific Aurora cluster."""
    try:
        rds = get_rds_client(aws_account_alias)
        response = rds.describe_db_clusters(DBClusterIdentifier=cluster_id)

        if response.get('DBClusters'):
            cluster = response['DBClusters'][0]
            return {
                "writer": cluster.get('Endpoint'),
                "reader": cluster.get('ReaderEndpoint'),
                "port": cluster.get('Port'),
            }
        return {}
    except Exception as e:
        return {}


def list_ssm_instances(aws_account_alias: str = None) -> List[Dict[str, Any]]:
    """List EC2 instances available for SSM connections."""
    try:
        ssm = get_ssm_client(aws_account_alias)
        response = ssm.describe_instance_information()
        instances = []

        for instance in response.get('InstanceInformationList', []):
            instances.append({
                "id": instance.get('InstanceId'),
                "name": instance.get('ComputerName'),
                "platform": instance.get('PlatformType'),
                "status": instance.get('PingStatus'),
            })

        return instances
    except Exception as e:
        return []


def get_instance_name(instance_id: str, aws_account_alias: str = None) -> Optional[str]:
    """Get the Name tag of an EC2 instance."""
    try:
        ec2 = get_ec2_client(aws_account_alias)
        response = ec2.describe_instances(InstanceIds=[instance_id])

        for reservation in response.get('Reservations', []):
            for instance in reservation.get('Instances', []):
                for tag in instance.get('Tags', []):
                    if tag.get('Key') == 'Name':
                        return tag.get('Value')
        return None
    except Exception as e:
        return None


def verify_ssm_instance(instance_id: str, aws_account_alias: str = None) -> Dict[str, Any]:
    """Verify that an EC2 instance is available for SSM connections."""
    try:
        ssm = get_ssm_client(aws_account_alias)
        response = ssm.describe_instance_information(
            Filters=[{'Key': 'InstanceIds', 'Values': [instance_id]}]
        )

        instances = response.get('InstanceInformationList', [])
        if instances:
            instance = instances[0]
            return {
                "available": True,
                "status": instance.get('PingStatus'),
                "platform": instance.get('PlatformType'),
            }
        return {
            "available": False,
            "error": "Instance not found or SSM agent not running",
        }
    except Exception as e:
        return {
            "available": False,
            "error": str(e),
        }
