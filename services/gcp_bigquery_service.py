
from google.cloud import bigquery
from google.cloud import dlp_v2
from google.cloud.dlp_v2 import types
import re

gbq_misconfigs = []

def query_data():
    client = bigquery.Client()
    query = "SELECT * FROM `capstone-test-project-450805.employee.employee` LIMIT 10"
    results = client.query(query)
    for row in results:
        print(row)


# def get_iam_permissions(project_id, dataset_id):
#     # Initialize the BigQuery client
#     client = bigquery.Client(project=project_id)
#
#     # Fetch IAM policy for the dataset
#     dataset_ref = client.dataset(f"{dataset_id}")
#     policy = client.get_dataset(dataset_ref).iam_policy()
#
#     print(f"Permissions for dataset {dataset_id}:")
#     for binding in policy.bindings:
#         print(f"Role: {binding['role']}")
#         for member in binding['members']:
#             print(f"  Member: {member}")


def scan_bigquery_table(project_id, dataset_id, table_id):
    # Initialize the DLP client
    dlp_client = dlp_v2.DlpServiceClient()

    # Define the BigQuery table to scan
    bigquery_table = types.BigQueryTable(
        project_id=project_id,
        dataset_id=dataset_id,
        table_id=table_id
    )

    # Configure the inspection job
    inspect_config = types.InspectConfig(
        info_types=[
            {"name": "EMAIL_ADDRESS"},
            {"name": "PHONE_NUMBER"},
            {"name": "CREDIT_CARD_NUMBER"}
        ],
        include_quote=True
    )

    storage_config = types.StorageConfig(
        big_query_options=types.BigQueryOptions(
            table_reference=bigquery_table
        )
    )

    # Create the inspection job
    parent = f"projects/{project_id}"
    job = {
        "inspect_config": inspect_config,
        "storage_config": storage_config
    }

    # Run the inspection job
    response = dlp_client.create_dlp_job(parent=parent, inspect_job=job)
    print(f"Created DLP job: {response.name}")

def get_dataset_iam_policy(project_id, dataset_id, table_id=None):
    client = bigquery.Client(project=project_id)
    # resource_path = f'projects/{project_id}/datasets/{dataset_id}'
    # print(f"Resource path of dataset {resource_path}:")

    dataset_ref = bigquery.DatasetReference(project_id, dataset_id)
    policy = client.get_iam_policy(dataset_ref)

    # if table_id:
    #     resource_path += f'/tables/{table_id}'
    #
    # # Get IAM policy
    # policy = client.get_iam_policy(resource_path)
    return policy

def get_table_iam_policy(project_id, dataset_id, table_id):
    client = bigquery.Client(project=project_id)
    table_ref = bigquery.TableReference.from_string(f'{project_id}.{dataset_id}.{table_id}')
    policy = client.get_iam_policy(table_ref)
    return policy

def check_table_access_controls(project_id, dataset_id, table_id):
    client = bigquery.Client(project=project_id)
    table_ref = bigquery.TableReference.from_string(f'{project_id}.{dataset_id}.{table_id}')
    table = client.get_table(table_ref)

    # Access the "access" property from the table's metadata
    if 'access' in table._properties:
        print(f"Access controls for table {table_id}:")
        for entry in table._properties['access']:
            role = entry.get('role', 'Unknown Role')
            entity_type = list(entry.keys() - {'role'})[0]  # Extracts the entity type
            entity = entry.get(entity_type, 'Unknown Entity')
            print(f"Role: {role}, Entity Type: {entity_type}, Entity: {entity}")
    else:
        print(f"No access control entries found for table {table_id}.")
        gbq_misconfigs.append({"message": f"No control entries found for table {table_id}" +"| IAM roles or ACLs need to be defined for the table",
             "criticality": "Medium"})

def check_table_last_modified(project_id, dataset_id, table_id):
    client = bigquery.Client(project=project_id)
    table_ref = bigquery.TableReference.from_string(f'{project_id}.{dataset_id}.{table_id}')
    table = client.get_table(table_ref)

    print(f"Table {table_id} was last modified on {table.modified}.")

def check_table_encryption_config(client, project_id, dataset_id, table_id):
    table_name = f"{project_id}.{dataset_id}.{table_id}"
    table_info = client.get_table(table_name)
    if table_info.encryption_configuration:
        print(f"Table {table_id} uses CMEK: {table_info.encryption_configuration.kms_key_name}")
    else:
        print(f"Table {table_id} does not use CMEK.")
        gbq_misconfigs.append({"message": f"Table {table_id} does not use CMEK" + "| Enable CMEK on tables to better control encryption",
                                  "criticality": "Low"})

def scan_table_for_pii(project_id, dataset_id, table_id):
    client = bigquery.Client()

    # Query the table
    query = f"SELECT * FROM `{project_id}.{dataset_id}.{table_id}` LIMIT 1000"


    query_job = client.query(query)
    results = query_job.result()

    # Define PII patterns
    pii_patterns = {
        "Email Address": r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
        "Credit Card Number": r'\b(?:\d[ -]*?){13,16}\b',  # 13 to 16 digits for credit cards
        "SSN": r'\b\d{3}-\d{2}-\d{4}\b',  # XXX-XX-XXXX pattern for SSN
        "Phone Number": r'\+?[0-9]{1,3}[-.\s]?[0-9]{2,4}[-.\s]?[0-9]{3,4}[-.\s]?[0-9]{3,4}'
    }

    # Scan for PII
    for row in results:
        for field, value in row.items():
            if isinstance(value, str):  # Only scan string fields
                matches = []  # Keep track of matched PII types for a single field
                for pii_type, pattern in pii_patterns.items():
                    if re.search(pattern, value):
                        matches.append(pii_type)

                # Print all identified matches for the field
                if matches:
                    print(f"\033[1;31m Potential PII/PHI/PCI violation in column '{field}' ({', '.join(matches)}): {value} \033[0m")
                    gbq_misconfigs.append({"message": f"PII/PHI/PCI violation ' ({', '.join(matches)})" +"| Protect/Restrict sensitive data by applying Data masking or column-level security", "criticality": "High"})

def scan_datasets_and_tables(project_id):
    print("\033[1m\033[34mGOOGLE BIGQUERY -  Scan Results\033[0m")
    # Initialize the BigQuery client
    client = bigquery.Client()

    # List datasets (databases)
    datasets = client.list_datasets()

    print(f"Datasets in project {project_id}:")
    for dataset in datasets:
        print(f"Dataset: {dataset.dataset_id}")
        # Fetch IAM permissions for the dataset
        #get_iam_permissions(project_id, dataset)
        #dataset_policy = get_iam_policy(project_id, dataset.dataset_id)
        # dataset_policy = get_dataset_iam_policy(project_id, dataset.dataset_id)
        # print('Dataset IAM Policy:')
        # for binding in dataset_policy.bindings:
        #     print(f'Role: {binding["role"]}')
        #     for member in binding["members"]:
        #         print(f' - Member: {member}')

        # For each dataset, list tables
        tables = client.list_tables(dataset.dataset_id)
        for table in tables:
            # Fetch IAM permissions for the table
            #get_table_permissions(project_id, dataset, table)
            table_policy = get_table_iam_policy(project_id, dataset.dataset_id, table.table_id)
            print('\nIAM Policy of Table:' + f'    - \033[1m{table.table_id}\033[0m')
            for binding in table_policy.bindings:
                print(f'Role: {binding["role"]}')
                for member in binding["members"]:
                    print(f' - Member: {member}')
            #scan_bigquery_table(project_id, dataset.dataset_id, table.table_id)
            check_table_encryption_config( client, project_id, dataset.dataset_id, table.table_id)
            check_table_access_controls(project_id, dataset.dataset_id, table.table_id)
            check_table_last_modified(project_id, dataset.dataset_id, table.table_id)
            scan_table_for_pii(project_id, dataset.dataset_id, table.table_id)

    return gbq_misconfigs