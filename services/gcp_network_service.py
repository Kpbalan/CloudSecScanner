# Copyright (c) 2025 Krishna Prasad Balan
#
# This file is licensed under the MIT License. See the LICENSE file for details.

from google.cloud import asset_v1

nw_misconfigs = []

def scan_firewall_rules(project_id):
    """Scan for overly permissive firewall rules."""
    client = asset_v1.AssetServiceClient()
    scope = f"projects/{project_id}"

    # List all firewall rules
    response = client.list_assets(
        request={
            "parent": scope,
            "asset_types": ["compute.googleapis.com/Firewall"],
            "content_type": asset_v1.ContentType.RESOURCE
        }
    )

    print("Checking for overly permissive firewall rules:")

    # Process each firewall rule
    for asset in response:
        firewall = asset.resource.data
        name = firewall.get("name")
        inactive = firewall.get("disabled")
        source_ranges = firewall.get("sourceRanges", [])
        allowed = firewall.get("allowed", [])

        # Check for source range allowing all traffic (0.0.0.0/0)
        if "0.0.0.0/0" in source_ranges and not inactive:
            print(f"Firewall Rule: {name}")
            print(f"  Source Ranges: {source_ranges}")
            for allow_rule in allowed:
                print(f"  Allowed Protocol/Ports: {allow_rule}")
                nw_misconfigs.append({"message": f"CIS violation allowing all traffic in f/w rule '{name}'" + "| Amend the firewall rule to not allow all traffic (0.0.0.0/0)",
                                          "criticality": "Critical"})
            print("---")
        else:
            print(f"Firewall Rule: {name} - No overly permissive source range.")

        logging_config = firewall.get("loggingConfig", {})

        # Check if logging is enabled
        if not logging_config:
            print(f"Resource: {name} - Logging not enabled.")
            nw_misconfigs.append({"message": f"CIS violation - misconfiguration not logging traffic in '{name}'" + "| Update the network rule to enable logging",
                                     "criticality": "High"})
        else:
            print(f"Resource: {name} - Logging enabled.")


def scan_network_assets(project_id):
    scan_firewall_rules(project_id)
    return nw_misconfigs


