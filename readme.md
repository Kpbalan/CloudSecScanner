### GCP CloudSecScanner

CloudSecScanner is a scanning tool that scans a GCP project for the presence of any misconfigurations.
It is currently designed to scan GCP components like Google Cloud Storage(GCS), Google BigQuery (GBQ) and
Google Kubernetes Engine (GKE). This tool uses Google APIs to establish connections and perform scanning on the cloud components.
Hence it can be made to execute the scan outside the Google project; it need not be installed/deployed within the environment of a google project.

### Pre-requisites

- Admin account

CloudSec Scanner needs to run as a Service Account that has either "Admin" or equivalent credentials. Please follow the below steps to create an admin-like service account.
1. In the Google Cloud console, navigate to IAM & Admin --> Service Accounts
2. Click "+Create Service Account" and provide a name and description
3. Select the following roles for the Service Account,  save and continue.
    
    - Access Context Manager Admin 
    - BigQuery Admin
    - BigQuery Data Policy Admin
    - BigQuery Data Viewer
    - BigQuery Metadata Viewer
    - Container Analysis Admin
    - CustomBigQueryIamPolicyViewer
    - DLP Administrator
    - DLP Connections Admin
    - DLP Data Profiles Admin
    - DLP Jobs Editor
    - IAP Policy Admin
    - Kubernetes Engine Admin
    - Kubernetes Engine Cluster Admin
    - Kubernetes Engine Cluster Viewer
    - Storage Admin
    - Storage Folder Admin


### credentials.json
1. For the CloudSecScanner to establish connection with the Google project that needs to be scanned, navigate to the project's Google Cloud Console
 and go to IAM & Admin --> Service Accounts"
2. Select the admin service account(created with the roles as mentioned above) . click Keys --> Add key --> Create new key
3. Choose JSON and then click Create to download a json file; Replace this with the "credentials.json" in the parent path.

### Add principal
Though the scanner would run as the above mentioned Service Account, it is necessary that we add our google account as a Principal and grant access to the Service account
1. Navigate to the project's Google Cloud Console and go to IAM & Admin --> Service Accounts
2. Choose the service account and Grant Access; add your google account(gmail)

### Tools/Libraries requirements
Check the requirements.txt and ensure all the python tools listed in the file are installed.
These tools are necessary for the functioning of the scanner as well as for Report generation.


### How to run the scanner?

1. Execute the below commands from the command line  to authenticate and login to the google cloud

   - `gcloud auth login`
   - `gcloud auth application-default login`

2. If you are executing the scan from an IDE environment (like PyCharm), go to "Run" and click "Run 'main'"; To run the scan from command like, execute the below command
    - `python3 main.py`

### Where to see the scan report/results?
Once the scan is completed, the results will be generated in a PDF file (`CloudSecScanner_Misconfigurations_Report.pdf`) under the parent path.
