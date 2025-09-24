#!/usr/bin/env python3
import os
import sys
import argparse
import time
from datetime import datetime
from typing import List

from snyk_export import SnykExportAPI


def export_for_org(snyk: SnykExportAPI, org_id: str, org_name: str, export_format: str, timeout_seconds: int = 600) -> List[str]:
    downloaded_files: List[str] = []
    datasets = ["issues", "dependencies"]

    for dataset in datasets:
        try:
            export_result = snyk.start_export(
                export_type=dataset,
                org_id=org_id,
                formats=[export_format]
            )
            if not export_result or "data" not in export_result or "id" not in export_result["data"]:
                print(f"Failed to start {dataset} export for {org_name} ({org_id})")
                continue

            export_id = export_result["data"]["id"]
            start_time = time.time()
            attempt = 0
            while True:
                attempt += 1
                status = snyk.get_export_status(export_id, org_id, dataset)
                export_status = status.get("data", {}).get("status", "unknown").lower()
                if export_status == "complete":
                    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                    safe_org = "".join(c if c.isalnum() else "_" for c in (org_name or "unknown"))
                    out_file = f"snyk_export_{safe_org}_{org_id[:8]}_{dataset}_{ts}.{export_format}"
                    path = snyk.download_export(status, out_file, export_format)
                    if path:
                        downloaded_files.append(path)
                    break
                if export_status in ("failed", "cancelled"):
                    print(f"{dataset.capitalize()} export {export_status} for {org_name} ({org_id})")
                    break
                if time.time() - start_time > timeout_seconds:
                    print(f"Timeout waiting for {dataset} export for {org_name} ({org_id})")
                    break
                time.sleep(5)
        except Exception as e:
            print(f"Error exporting {dataset} for {org_name} ({org_id}): {e}")
    return downloaded_files


def main():
    parser = argparse.ArgumentParser(description="Run non-interactive Snyk exports and optionally combine results")
    parser.add_argument("--token", required=True, help="Snyk API token")
    parser.add_argument("--group", required=False, help="Group ID to list organizations from or run group export")
    parser.add_argument("--org-id", required=False, help="Single organization ID to export (overrides --group org listing)")
    parser.add_argument("--format", choices=["csv", "json"], default="csv", help="Export format")
    parser.add_argument("--combine", choices=["yes", "no"], default="yes", help="Combine downloaded files of same format")
    parser.add_argument("--timeout", type=int, default=600, help="Timeout in seconds per dataset export")
    parser.add_argument("--group-export", action="store_true", help="Use group-level export endpoint (/groups/{group}/export)")
    parser.add_argument("--region", choices=["1","2"], default="1", help="Region: 1=US, 2=EU")
    parser.add_argument("--poll-interval", type=int, default=120, help="Seconds to wait between status checks")

    args = parser.parse_args()

    base_url = "https://api.snyk.io/rest" if args.region == "1" else "https://api.eu.snyk.io/rest"
    snyk = SnykExportAPI(args.token, base_url=base_url)

    downloaded: List[str] = []

    try:
        if args.group_export:
            if not args.group:
                print("--group is required when using --group-export")
                return 1
            # Build filters with all orgs in the group
            orgs = snyk.list_organizations(args.group) or []
            org_ids = [o.get("id") for o in orgs if o.get("id")]
            # Default: restrict to last 30 days introduced window to satisfy some tenants
            from datetime import timedelta
            now = datetime.utcnow()
            introduced_from = (now - timedelta(days=30)).strftime("%Y-%m-%dT00:00:00Z")
            introduced_to = now.strftime("%Y-%m-%dT00:00:00Z")
            filters = {"orgs": org_ids, "introduced": {"from": introduced_from, "to": introduced_to}}
            if not org_ids:
                print("No organizations found for the specified group; cannot start group export.")
                return 1
            # Columns per dataset (per Snyk docs)
            columns_issues = [
                "ISSUE_SEVERITY_RANK",
                "ISSUE_SEVERITY",
                "SCORE",
                "PROBLEM_TITLE",
                "CVE",
                "CWE",
                "ORG_PUBLIC_ID",
                "PROJECT_PUBLIC_ID",
                "PROJECT_NAME",
                "PROJECT_URL",
                "EXPLOIT_MATURITY",
                "AUTOFIXABLE",
                "FIRST_INTRODUCED",
                "PRODUCT_NAME",
                "ISSUE_URL",
                "ISSUE_STATUS_INDICATOR",
                "ISSUE_TYPE",
            ]
            columns_usage = [
                "ID",
                "ORG_PUBLIC_ID",
                "GROUP_PUBLIC_ID",
                "PRODUCT_DISPLAY_NAME",
                "INTERACTION_TYPE",
                "INTERACTION_TIMESTAMP",
                "INTERACTION_STATUS",
                "UPDATED_AT",
            ]
            # Run both datasets: issues and usage (per docs)
            downloaded_datasets: List[str] = []
            # Start with issues dataset to ensure endpoint compatibility
            for dataset in ("issues",):
                result = snyk.start_group_export(
                    group_id=args.group,
                    dataset=dataset,
                    columns=(columns_issues if dataset == "issues" else columns_usage),
                    filters=filters,
                    formats=[args.format],
                )
                if not result or "data" not in result or "id" not in result["data"]:
                    print(f"Failed to start group export for dataset {dataset}")
                    continue
                export_id = result["data"]["id"]
                start = time.time()
                while True:
                    status = snyk.get_group_export_status(args.group, export_id)
                    state = status.get("data", {}).get("attributes", {}).get("status", "unknown").lower()
                    if state in ("complete", "finished"):
                        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                        out = f"snyk_group_export_{dataset}_{export_id}_{ts}.{args.format}"
                        path = snyk.download_group_export(args.group, status, out, args.format)
                        if isinstance(path, list):
                            downloaded.extend(path)
                        else:
                            downloaded.append(path)
                        downloaded_datasets.append(dataset)
                        break
                    if state in ("failed", "cancelled"):
                        print(f"Group export {state} for dataset {dataset}")
                        break
                    if time.time() - start > args.timeout:
                        print(f"Group export timeout for dataset {dataset}")
                        break
                    time.sleep(args.poll_interval)
            # end datasets loop
        elif args.org_id:
            downloaded.extend(export_for_org(snyk, args.org_id, args.org_id, args.format, args.timeout))
        else:
            if not args.group:
                print("Either --org-id or --group must be provided")
                return 1
            orgs = snyk.list_organizations(args.group)
            if not orgs:
                print(f"No organizations found for group {args.group}")
                return 1
            for org in orgs:
                oid = org.get("id")
                oname = org.get("name", "unknown")
                print(f"Exporting organization: {oname} ({oid})")
                downloaded.extend(export_for_org(snyk, oid, oname, args.format, args.timeout))
                time.sleep(2)

        print("\nDownloaded files:")
        for f in downloaded:
            print(f"- {f}")

        if args.combine == "yes" and len(downloaded) >= 2:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            # Save combined file in same folder as first downloaded file
            import os
            first_dir = os.path.dirname(downloaded[0]) or "."
            if args.format == "json":
                json_files = [f for f in downloaded if f.lower().endswith(".json")]
                if len(json_files) >= 2:
                    combined = os.path.join(first_dir, f"snyk_combined_export_{timestamp}.json")
                    if snyk.combine_json_files(json_files, combined):
                        print(f"Combined JSON saved to: {combined}")
            else:
                csv_files = [f for f in downloaded if f.lower().endswith(".csv")]
                if len(csv_files) >= 2:
                    combined = os.path.join(first_dir, f"snyk_combined_export_{timestamp}.csv")
                    if snyk.combine_csv_files(csv_files, combined):
                        print(f"Combined CSV saved to: {combined}")

        return 0
    except KeyboardInterrupt:
        print("Interrupted by user")
        return 1


if __name__ == "__main__":
    sys.exit(main())


