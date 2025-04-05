# Copyright (c) 2025 Krishna Prasad Balan
#
# This file is licensed under the MIT License. See the LICENSE file for details.

from datetime import datetime, timezone, timedelta

from colorama import init
from google.cloud import storage
from tabulate import tabulate

from utils.helpers import color_value

init()

RESET = "\033[0m"
BOLD = "\033[1m"
RED = "\033[31m"
BLUE = "\033[34m"
GREEN = "\033[32m"

gcs_misconfigs = []

def create_bucket(bucket_name):
    """Creates a new bucket."""
    # Initialize a storage client
    client = storage.Client()

    # Create the new bucket
    bucket = client.bucket(bucket_name)
    bucket.create()

    print(f'Bucket {bucket_name} created.')

def list_yaml_files(bucket_name):
    """Lists all YAML files in the specified GCS bucket."""
    # Initialize a storage client
    client = storage.Client()

    # Get the bucket
    bucket = client.bucket(bucket_name)

    # List all objects in the bucket
    blobs = bucket.list_blobs()

    # Filter for YAML files
    yaml_files = [blob.name for blob in blobs if blob.name.endswith('.yaml')]

    return yaml_files

def get_bucket_configuration(bucket_name, report_file):
    """Fetches and prints the configuration of a GCS bucket in YAML format."""
    # Initialize a storage client
    client = storage.Client()

    # Get the bucket
    bucket = client.bucket(bucket_name)

    # Fetch bucket metadata
    bucket.reload()

    # Fetch the bucket's ACL
    bucket_acl = bucket.acl

    # Check if Uniform Bucket-Level Access is enabled
    insecure_grants = []
    if bucket.iam_configuration.uniform_bucket_level_access_enabled:
        access_type = "Uniform Bucket-Level Access (bucket-level access)"
    else:
        access_type = "Legacy ACLs (object-level permissions)"
        gcs_misconfigs.append({"message": "Uniform Bucket-Level Access (bucket-level access) not enabled " +"| Enable Uniform bucket level access to enforce better control over accesses", "criticality": "Medium"})
         # Check for overly permissive grants
        for entry in bucket_acl:
            if entry['entity'] in ['allUsers', 'allAuthenticatedUsers']:
                insecure_grants.append(entry)
                gcs_misconfigs.append({"message": "Overly permissive ACL grants for " +entry +"| Remove broad access(allUsers/allAuthenticatedUsers) to the bucket", "criticality": "Medium"})


    # Check for customer-managed encryption key (CMEK)

    if bucket.default_kms_key_name:
        encryption_type = "Customer-managed encryption"
        kms_key = bucket.default_kms_key_name
        key = client.get_crypto_key(name=kms_key)
        # Check the key's creation and rotation times
        creation_time = key.create_time
        rotation_time = key.next_rotation_time

        # Convert timestamps to datetime objects
        creation_time = creation_time.timestamp().ToDatetime().replace(tzinfo=timezone.utc)
        rotation_time = rotation_time.timestamp().ToDatetime().replace(tzinfo=timezone.utc) if rotation_time else None

        # Calculate the time since the last rotation
        if rotation_time:
            time_since_rotation = datetime.now(timezone.utc) - rotation_time
        else:
            time_since_rotation = datetime.now(timezone.utc) - creation_time

        if  time_since_rotation > (datetime.now() - timedelta(days=730)):
            gcs_misconfigs.append({"message": "Customer-managed encryption key rotation time is greater than 2 years " +"| Update Key Rotation Schedule immediately" , "criticality": "High"})
        elif (datetime.now() - timedelta(days=730)) < time_since_rotation < (datetime.now() - timedelta(days=365)):
            gcs_misconfigs.append({"message": "Customer-managed encryption key rotation time is greater than 1 year but less than 2 years " +"| Update Key Rotation Schedule (ideally less than 6 months)", "criticality": "Medium"})
        elif (datetime.now() - timedelta(days=365)) < time_since_rotation < (datetime.now() - timedelta(days=180)):
            gcs_misconfigs.append({"message": "Customer-managed encryption key rotation time is greater than 6 months " +"| Update Key Rotation Schedule (ideally less than 6 months)", "criticality": "Low"})
        else:
            print("Customer-managed encryption key rotation time is lesser than 6 months - good")
    else:
        encryption_type = "Google-managed encryption"
        kms_key = None

    # Fetch the bucket's IAM policy
    policy = bucket.get_iam_policy()

    # Define overly permissive roles to look for
    basic_accesse_roles = [
        'roles/storage.objectViewer',
        'roles/storage.legacyBucketReader'
    ]

    # Define overly permissive roles to look for
    overly_permissive_roles = [
        'roles/storage.objectViewer',
        'roles/storage.legacyBucketReader',
        'roles/storage.legacyBucketOwner',
        'roles/storage.legacyBucketWriter'
    ]

    # Check if any role bindings grant Public access to 'allUsers' or 'allAuthenticatedUsers'
    is_public_access = any(
        binding['role'] in basic_accesse_roles and
        ('allUsers' in binding['members'] or 'allAuthenticatedUsers' in binding['members'])
        for binding in policy.bindings
    )
    if is_public_access:
        gcs_misconfigs.append({"message": "Public bucket access for the bucket {" +bucket.name +"}| Remove Public access(allUsers/allAuthenticatedUsers) to the bucket",
                               "criticality": "Critical"})
    # Check if any role bindings grant access to 'allUsers' or 'allAuthenticatedUsers'
    overly_permissive_role_bindings_arr = [
        binding for binding in policy.bindings
        if binding['role'] in overly_permissive_roles and
        ('allUsers' in binding['members'] or 'allAuthenticatedUsers' in binding['members'])
    ]

    overly_permissive_role_bindings = ""
    if overly_permissive_role_bindings_arr:
        print("Overly permissive roles found in bucket IAM policy")
        #report_file.write(f"{RED}" + bucket.name + f"{RESET}")

        for binding in overly_permissive_role_bindings_arr:
            overly_permissive_role_bindings += f"Role: {binding['role']}, Members: {binding['members']}"
            gcs_misconfigs.append({"message" :f"Overly permissive roles found in bucket IAM policy " +"| Apply 'Principle of Least Privilege'/remove broad permissions" , "criticality": "Medium"} )
    else:
        overly_permissive_role_bindings += "None"

    has_overly_permissive_role_bindings = False
    if overly_permissive_role_bindings_arr and overly_permissive_role_bindings_arr[0] != 'None':
        has_overly_permissive_role_bindings = True

    # Extract relevant configuration details
    bucket_config = {
        'bucket_name': bucket.name,
        'location': bucket.location,
        'storage_class': bucket.storage_class,
        'versioning_enabled': bucket.versioning_enabled,
        'lifecycle_rules': [rule.to_api_repr() for rule in bucket.lifecycle_rules],
        'public_access_enabled': is_public_access,
        'has_overly_permissive_role_bindings': has_overly_permissive_role_bindings,
        'overly_permissive_role_bindings': overly_permissive_role_bindings,
        'encryption_type' : encryption_type,
        'kms_key' : kms_key,
        'ACL_access_type': access_type,
        'insecure_access_control_grants': insecure_grants
    }


    return bucket_config

def scan_buckets(project_id, report_file):
    print("\033[1m\033[34mGOOGLE CLOUD STORAGE - Scan Results\033[0m")
    """Lists all buckets."""
    # Initialize a storage client
    client = storage.Client(project=project_id)

    # Retrieve and list all buckets
    buckets = client.list_buckets()

    for bucket in buckets:
        print(f"{RED}" +bucket.name +f"{RESET}")
        #report_file.write(f"{RED}" +bucket.name +f"{RESET}")
        # Get the bucket configuration in YAML format
        bucket_config_dict = get_bucket_configuration(bucket.name, report_file)
        print("Bucket Configuration:")
        #report_file.write("Bucket Configuration:")
        # Convert dictionary to list of tuples
        table_data = [(key, color_value(key, value)) for key, value in bucket_config_dict.items()]

        # Display the table
        print(tabulate(table_data, headers=['Security Config', 'Value'], tablefmt='grid'))
        #report_file.write(tabulate(table_data, headers=['Security Config', 'Value'], tablefmt='grid'))

    return gcs_misconfigs


if __name__ == "__main__":

    # List all buckets
    scan_buckets()