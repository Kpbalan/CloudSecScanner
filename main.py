import os

import matplotlib.pyplot as plt
import pandas as pd
from google.oauth2 import service_account

from services import gcp_storage_service, gcp_kubernetes_service, gcp_bigquery_service
from utils.helpers import scan_file_pdf_converter, capture_misconfigs_trend_to_csv

# Set the path to your Google Cloud service account key
os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = "credentials.json"
os.environ["GOOGLE_CLOUD_PROJECT"] = "capstone-test-project-450805"
credentials = service_account.Credentials.from_service_account_file('credentials.json')
report_file_path = "vulnerability_scan.txt"
pdf_report = "CloudSecScanner_Misconfigurations_Report.pdf"
misconfigs_trend_file="misconfigs_trend.csv"
criticality_chart = "criticality_chart.png"
trend_graph = "trend_graph.png"

def main():
    # Initialize a dict for misconfiguration issues and their criticality
    criticality_summary = {
        "Critical": [],
        "High": [],
        "Medium": [],
        "Low": []
    }

    # Misconfiguration issues list with criticality
    misconfigs = []

    # Specify the default project ID
    project_id = "capstone-test-project-450805"
    location = 'us-east1-b'

    #initiate_scan_report_file(report_file_path)

    try:
        # Open the log file in write mode
        with open(report_file_path, 'w') as report_file:
            # Connect to Google Cloud Storage
            gcs_misconfigs = gcp_storage_service.scan_buckets(project_id, report_file)
            misconfigs.extend(gcs_misconfigs)

            # Connect to Google Kubernetes Engine (add your specific logic)
            gke_misconfigs = gcp_kubernetes_service.scan_kubernetes_clusters(credentials, project_id, location, report_file_path)
            misconfigs.extend(gke_misconfigs)

            # Connect to BigQuery (add your specific logic)
            gbq_misconfigs = gcp_bigquery_service.scan_datasets_and_tables(project_id)
            misconfigs.extend(gbq_misconfigs)

        # Iterate through each warning and sort by priority
        for misconfig in misconfigs:
            criticality = misconfig["criticality"]
            if criticality in criticality_summary:
                criticality_summary[criticality].append(misconfig["message"])

        # Count the number of warnings in each priority category
        criticality_counts = {key: len(value) for key, value in criticality_summary.items()}

        # Capture the trend
        capture_misconfigs_trend_to_csv(criticality_counts, misconfigs_trend_file)

        # Display the results
        with open(report_file_path, 'w') as report_file:
            print("Misconfiguration Criticality - Summary:")
            #report_file.write("Severity| Count| Misconfiguration \n")
            for criticality, messages in criticality_summary.items():
                print(f"{criticality} ({len(messages)} misconfigs):")
                #report_file.write(f"{criticality} : {len(messages)} :")
                for msg in messages:
                    print(f"  - {msg}")
                    #report_file.write(f" {criticality} | {len(messages)} |  - {msg} \n")
                    report_file.write(f" {criticality} |  - {msg}  \n")

            print("\nCounts by Criticality: \n")
            #report_file.write("\n\n\nCounts by Criticality: \n")
            print(criticality_counts)
            #report_file.write(str(criticality_counts))


        # Extract data for visualization
        labels = criticality_counts.keys()
        sizes = criticality_counts.values()
        colors = ['#ff0000', '#fb8500','#e4cd05' , '#add8e6']  # colors representing criticality
        explode = (0.2, 0.1, 0.1, 0.1)  # to highlight high and critical

        # Pie Chart
        plt.figure(figsize=(8, 6))
        plt.pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%', startangle=140, explode=explode)
        plt.title(' Misconfigurations by Criticality \n\n')
        #plt.show()
        plt.savefig(criticality_chart, format="png", dpi=300)  # Save as image
        plt.close()


        data = pd.read_csv(misconfigs_trend_file, parse_dates=["Timestamp"])
        data.set_index("Timestamp", inplace=True)

        # Plot the trends over time
        data.plot(figsize=(10, 6), marker='o')
        plt.title(" Misconfiguration Trend \n\n")
        plt.xlabel("Timestamp")
        plt.ylabel("Count")
        plt.grid(True, linestyle='--', alpha=0.6)
        plt.legend(title="Criticality Levels")
        plt.tight_layout()
        #plt.show()
        plt.savefig(trend_graph, format="png", dpi=300)  # Save as image
        plt.close()

    except Exception as e:
        print(f"An error occurred: {e}")

    charts = [criticality_chart, trend_graph]
    scan_file_pdf_converter(report_file_path, pdf_report, charts)

if __name__ == "__main__":
    main()