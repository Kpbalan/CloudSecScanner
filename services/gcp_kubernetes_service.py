# Copyright (c) 2025 Krishna Prasad Balan
#
# This file is licensed under the MIT License. See the LICENSE file for details.

from google.cloud import container_v1
from google.auth import default
from google.cloud.devtools.containeranalysis_v1.types import containeranalysis
from kubernetes import client, config
from google.auth.transport.requests import Request
import os

kubeconfig_path = os.getenv('KUBECONFIG')

gke_misconfigs = []

def get_cluster_credentials(project_id, zone, cluster_name):
    # Initialize the GKE client
    client = container_v1.ClusterManagerClient()

    # Get cluster details
    cluster = client.get_cluster(name=f"projects/{project_id}/locations/{zone}/clusters/{cluster_name}", project_id=project_id, zone=zone)
    print(f"Cluster Version: {cluster.current_master_version}")
    print(f"Cluster Status: {cluster.status}")
    print(f"Cluster Endpoint: {cluster.endpoint}")
    print(f"Cluster Network: {cluster.network}")

    # Return cluster endpoint and authentication details
    return cluster.endpoint, cluster.master_auth

def configure_kubernetes_client( endpoint, master_auth):
    # Configure Kubernetes client
    configuration = client.Configuration()
    configuration.host = f"https://{endpoint}"
    configuration.verify_ssl = False
    configuration.api_key = {"authorization": "Bearer " + master_auth.cluster_ca_certificate}
    client.Configuration.set_default(configuration)

def check_missing_resource_limits(pod):
    for container in pod.spec.containers:
            if not container.resources.limits:
                print(f"\033[1;31m Pod {pod.metadata.name} in namespace {pod.metadata.namespace} has no resource limits set. \033[0m")
                gke_misconfigs.append({"message": f"Pod {pod.metadata.name} in namespace {pod.metadata.namespace} has no resource limits set " +"| Memory and CPU settings needed for pod; use kubectl to configure.",
                                      "criticality": "Low"})

def check_privileged_containers(pod):
    for container in pod.spec.containers:
            if container.security_context and container.security_context.privileged:
                print(f"\033[1;31m Pod {pod.metadata.name} in namespace {pod.metadata.namespace} has a privileged container. \033[0m")
                gke_misconfigs.append({"message": f"Pod {pod.metadata.name} in namespace {pod.metadata.namespace} has a privileged container " +"| Memory and CPU settings needed for pod; use kubectl to configure.",
                                      "criticality": "Medium"})

def check_exposed_services(v1):
    services = v1.list_service_for_all_namespaces()
    exposed_services = []
    for service in services.items:
        if service.spec.type == "LoadBalancer":
            exposed_services.append(f"\033[1;31m Service {service.metadata.name} in namespace {service.metadata.namespace} is exposed via LoadBalancer. \033[0m")
            gke_misconfigs.append({"message": f"Service {service.metadata.name} in namespace {service.metadata.namespace} is exposed via LoadBalancer " +"| Define restrictive role bindings and apply them via Pod security policies",
                                      "criticality": "High"})
    return exposed_services

def scan_pods():
    credentials, project = default(scopes=["https://www.googleapis.com/auth/cloud-platform"])
    # If needed, refresh the token
    if credentials.expired:
        credentials.refresh(Request())
    #Use Kubernetes CoreV1 API to list pods
    config.load_kube_config()
    v1 = client.CoreV1Api()
    exposed_services = check_exposed_services(v1)
    exposed_svcs = str(exposed_services)
    exposed_services_list = {
        'Exposed Services': {exposed_svcs}
    }

    pods = v1.list_namespaced_pod(namespace='default')
    if pods.items:
        for pod in pods.items:
            print(f"Pod Name: {pod.metadata.name}, Namespace: {pod.metadata.namespace}")
            check_missing_resource_limits(pod)
            check_privileged_containers(pod)

def scan_unpatched_vuln_occurences(project_id):
    client = containeranalysis.ContainerAnalysisClient()

    filter_expression = 'kind="VULNERABILITY"'
    parent = f"projects/{project_id}"

    occurrences = client.list_occurrences(parent=parent, filter=filter_expression)

    for occurrence in occurrences:
        print(f"Vulnerability: {occurrence.note_name}")
        print(f"Severity: {occurrence.vulnerability.effective_severity}")
        print(f"Description: {occurrence.vulnerability.short_description}")

def check_cluster_role_bindings():
    # Load kubeconfig
    config.load_kube_config()

    # API instance for RBAC
    rbac_api = client.RbacAuthorizationV1Api()
    # Fetch all ClusterRoleBindings
    cluster_role_bindings = rbac_api.list_cluster_role_binding()

    print("Checking ClusterRoleBindings for misconfigurations...\n")

    # Analyze each ClusterRoleBinding
    for binding in cluster_role_bindings.items:
        print(f"ClusterRoleBinding: {binding.metadata.name}")

        # Check the roleRef (role being bound)
        role_ref = binding.role_ref
        print(f" - Role: {role_ref.name}")
        print(f" - Kind: {role_ref.kind}")

        # Flag if the binding grants 'cluster-admin'
        if role_ref.name == "cluster-admin":
            print("\033[1;31m   * Warning: Grants 'cluster-admin' role. Ensure this is necessary.\033[0m")
            gke_misconfigs.append({"message": "Overly permissive 'cluster-admin' role granted for : " +binding.metadata.name +"| Apply restrictive role bindings and remove broad grants/permissions",
                                   "criticality": "Medium"})

        # Check the subjects (users/groups/service accounts) bound to the role
        if binding.subjects:
            for subject in binding.subjects:
                print(f" - Subject Kind: {subject.kind}, Name: {subject.name}, Namespace: {subject.namespace if subject.namespace else 'N/A'}")

                if subject.kind == "Group" and subject.name == "system:masters":
                    print(f"\033[1;31m   * Warning: The 'system:masters' group has cluster-wide administrative access.\033[0m")
                    gke_misconfigs.append({"message": "The 'system:masters' group has cluster-wide administrative access " +"| Remove broad grants/permissions from the group", "criticality": "Medium"})
        else:
            print("\033[1;31m   * Warning: No subjects found for this ClusterRoleBinding, which may indicate misconfiguration.\033[0m")
            gke_misconfigs.append({"message": "No subjects found for this ClusterRoleBinding: " +binding.metadata.name +"| Either add subjects to the role binding or remove the binding(if not needed)",
                                   "criticality": "Low"})

        print("")  # Newline for readability


def scan_kubernetes_clusters(credentials, project_id, location, report_file_path):
    print("\033[1m\033[34mGOOGLE KUBERNETES ENGINE -  Scan Results\033[0m")

    # Initialize the client for the Container API
    client = container_v1.ClusterManagerClient(credentials=credentials)

    #scan_unpatched_vuln_occurences(project_id)

    # List clusters in the specified project and location
    clusters = client.list_clusters(project_id=project_id, zone=location)

    check_cluster_role_bindings()

    for cluster in clusters.clusters:
        endpoint, master_auth = get_cluster_credentials(project_id, cluster.location, cluster.name)
        # Configure Kubernetes client
        configure_kubernetes_client(endpoint, master_auth)
        scan_pods()

    return gke_misconfigs