import os
import sys
import json
import re
import csv
import uuid
import time
import requests
import pandas as pd
from datetime import datetime, timedelta, timezone
from typing import Optional, List, Dict, Any, Union, Tuple
from pathlib import Path
from dotenv import load_dotenv
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt, Confirm

# Initialize console
console = Console()

class SnykExportAPI:
    # API endpoints
    BASE_URL = "https://api.snyk.io/rest"
    GROUPS_PATH = "/orgs"
    ORGS_PATH = "/orgs"
    EXPORT_PATH = "/orgs/{org_id}/exports"
    EXPORT_STATUS_PATH = "/orgs/{org_id}/exports/{export_id}"
    EXPORT_DOWNLOAD_PATH = "/orgs/{org_id}/exports/{export_id}/download"
    GROUP_EXPORT_PATH = "/groups/{group_id}/export"
    GROUP_EXPORT_STATUS_PATH = "/groups/{group_id}/export/{export_id}"
    GROUP_EXPORT_DOWNLOAD_PATH = "/groups/{group_id}/export/{export_id}/download"
    API_VERSION = "2024-10-15"
    V1_BASE = "https://api.snyk.io/v1"
    
    def __init__(self, api_token: str, org_id: Optional[str] = None, base_url: Optional[str] = None):
        """Initialize the SnykExportAPI client.
        
        Args:
            api_token: Snyk API token with appropriate permissions
            org_id: Optional organization ID to use as default
        """
        self.api_token = api_token
        self.org_id = org_id
        # Allow overriding API base (region). Defaults to US base.
        self.base_url = base_url or self.BASE_URL
        self.headers = {
            "Authorization": f"token {self.api_token}",
            "Content-Type": "application/vnd.api+json",
            "User-Agent": "snyk-export-tool/1.0"
        }
        self.headers_v1 = {
            "Authorization": f"token {self.api_token}",
            "Content-Type": "application/json",
            "User-Agent": "snyk-export-tool/1.0"
        }
        self._project_cache: Dict[Tuple[str, str], Dict[str, Any]] = {}
        self._policy_ignore_cache: Dict[str, Dict[str, Any]] = {}

    def get_project_v1(self, org_id: str, project_id: str) -> Dict[str, Any]:
        cache_key = (org_id, project_id)
        if cache_key in self._project_cache:
            return self._project_cache[cache_key]
        url = f"{self.V1_BASE}/org/{org_id}/project/{project_id}"
        r = requests.get(url, headers=self.headers_v1, timeout=30)
        r.raise_for_status()
        data = r.json()
        self._project_cache[cache_key] = data
        return data

    def get_org_policies(self, org_id: str) -> Dict[str, Any]:
        if org_id in self._policy_ignore_cache:
            return self._policy_ignore_cache[org_id]
        policies_url = f"{self.base_url}/orgs/{org_id}/policies?version={self.API_VERSION}"
        resp = requests.get(policies_url, headers=self.headers, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        ignore_map: Dict[str, Dict[str, Any]] = {}
        for item in data.get("data", []):
            attributes = item.get("attributes", {})
            if attributes.get("policy_type") != "ignore":
                continue
            reasons = attributes.get("reasons", [])
            for reason in reasons:
                for issue in reason.get("issues", []):
                    issue_id = issue.get("id") or issue.get("issue_id")
                    if issue_id:
                        ignore_map[issue_id] = {
                            "reason": reason.get("reason"),
                            "reason_type": reason.get("reason_type"),
                            "notes": reason.get("notes"),
                            "ignored_since": attributes.get("created_at"),
                            "ignore_data": reason,
                        }
        self._policy_ignore_cache[org_id] = ignore_map
        return ignore_map

    def enrich_export_files(self, files: List[str]) -> None:
        for file_path in files:
            if not file_path.lower().endswith(".csv"):
                continue
            try:
                df = pd.read_csv(file_path)
            except Exception as exc:
                console.print(f"[red]Failed to read {file_path}: {exc}")
                continue

            additional_cols = {
                "PROJECT_CREATED_AT": [],
                "PROJECT_TOTAL_DEPENDENCIES": [],
                "PROJECT_SEVERITY_COUNTS": [],
                "IGNORE_REASON": [],
                "IGNORE_REASON_TYPE": [],
                "IGNORE_NOTES": [],
                "IGNORED_SINCE": [],
            }

            for _, row in df.iterrows():
                org_id = row.get("ORG_PUBLIC_ID") or self.org_id
                project_id = row.get("PROJECT_PUBLIC_ID")
                project_created = ""
                project_dependencies = ""
                severity_counts = ""
                ignore_reason = ""
                ignore_reason_type = ""
                ignore_notes = ""
                ignored_since = ""

                if org_id and project_id:
                    try:
                        project = self.get_project_v1(org_id, project_id)
                        project_created = project.get("created", "")
                        project_dependencies = project.get("totalDependencies", "")
                        severity_counts = json.dumps(project.get("issueCountsBySeverity", {}))
                    except requests.HTTPError as http_exc:
                        console.print(f"[yellow]Project lookup failed for {project_id}: {http_exc}")
                    except Exception as exc:
                        console.print(f"[yellow]Project lookup error for {project_id}: {exc}")

                issue_id = row.get("ISSUE_URL")
                if issue_id:
                    match = re.search(r"issue-([^/?]+)", str(issue_id))
                    if match:
                        issue_key = match.group(1)
                    else:
                        issue_key = str(issue_id)
                else:
                    issue_key = row.get("PROBLEM_ID")

                if org_id and issue_key:
                    try:
                        policy_map = self.get_org_policies(org_id)
                        ignore_info = policy_map.get(issue_key)
                        if ignore_info:
                            ignore_reason = ignore_info.get("reason", "")
                            ignore_reason_type = ignore_info.get("reason_type", "")
                            ignore_notes = ignore_info.get("notes", "")
                            ignored_since = ignore_info.get("ignored_since", "")
                    except requests.HTTPError as http_exc:
                        console.print(f"[yellow]Policy lookup failed for {org_id}: {http_exc}")
                    except Exception as exc:
                        console.print(f"[yellow]Policy lookup error for {org_id}: {exc}")

                additional_cols["PROJECT_CREATED_AT"].append(project_created)
                additional_cols["PROJECT_TOTAL_DEPENDENCIES"].append(project_dependencies)
                additional_cols["PROJECT_SEVERITY_COUNTS"].append(severity_counts)
                additional_cols["IGNORE_REASON"].append(ignore_reason)
                additional_cols["IGNORE_REASON_TYPE"].append(ignore_reason_type)
                additional_cols["IGNORE_NOTES"].append(ignore_notes)
                additional_cols["IGNORED_SINCE"].append(ignored_since)

            for col, values in additional_cols.items():
                df[col] = values

            try:
                df.to_csv(file_path, index=False)
                console.print(f"[green]✓ Enriched export file with project metadata and ignore info: {file_path}")
            except Exception as exc:
                console.print(f"[red]Failed to write enriched data to {file_path}: {exc}")

    def start_group_export(
        self,
        group_id: str,
        dataset: str = "issues",
        columns: Optional[List[str]] = None,
        filters: Optional[Dict[str, Any]] = None,
        formats: List[str] = ["csv"],
    ) -> Dict[str, Any]:
        """Start a group-level export job.

        Args:
            group_id: Snyk group ID
            dataset: "issues" or "dependencies"
            columns: optional list of columns
            filters: optional filters dict (may include orgs, environment, lifecycle, introduced/updated ranges, etc.)
            formats: ["csv"] or ["json"]
        """
        if not group_id:
            raise ValueError("Group ID is required")

        payload: Dict[str, Any] = {
            "data": {
                "type": "resource",
                "attributes": {
                    "dataset": dataset,
                    "formats": [(formats[0] if formats else "csv").lower()],
                    "filters": filters or {},
                },
            }
        }
        if columns:
            payload["data"]["attributes"]["columns"] = columns

        headers = {
            "Content-Type": "application/vnd.api+json",
            "Accept": "application/vnd.api+json",
            "Authorization": f"token {self.api_token}",
            "Snyk-Request-Id": str(uuid.uuid4()),
        }

        # Use configured API version for group export
        url = f"{self.base_url}{self.GROUP_EXPORT_PATH.format(group_id=group_id)}?version={self.API_VERSION}"
        console.print(f"[dim]Starting group export via: {url}")
        try:
            response = requests.post(url, json=payload, headers=headers)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.HTTPError as he:
            # No legacy fallback for group export; surface error
            try:
                console.print(f"[red]Group export error detail: {response.text}")
            except Exception:
                pass
            raise

    def get_group_export_status(self, group_id: str, export_id: str) -> Dict[str, Any]:
        if not group_id or not export_id:
            raise ValueError("Group ID and export ID are required")
        primary = f"{self.base_url}{self.GROUP_EXPORT_STATUS_PATH.format(group_id=group_id, export_id=export_id)}?version={self.API_VERSION}"
        console.print(f"[dim]Checking group export status: {primary}")
        try:
            response = requests.get(primary, headers=self.headers)
            response.raise_for_status()
            data = response.json()
        except requests.exceptions.HTTPError:
            # Fallback to jobs path
            jobs_path = f"/groups/{group_id}/jobs/export/{export_id}"
            url_jobs = f"{self.base_url}{jobs_path}?version={self.API_VERSION}"
            console.print(f"[yellow]Status 404. Retrying via jobs path: {url_jobs}")
            try:
                response = requests.get(url_jobs, headers=self.headers)
                response.raise_for_status()
                data = response.json()
            except requests.exceptions.HTTPError:
                # If both fail, return a default status to continue
                console.print(f"[yellow]Both endpoints failed. Assuming export is in progress.")
                data = {
                    "data": {
                        "attributes": {
                            "status": "started"
                        }
                    }
                }
        # Normalize status to lowercase simple terms if present
        try:
            attrs = data.get('data', {}).get('attributes', {})
            status_val = attrs.get('status')
            if isinstance(status_val, str):
                attrs['status'] = status_val.lower()
                data['data']['attributes'] = attrs
        except Exception:
            pass
        return data

    def download_group_export(self, group_id: str, export_result: Dict[str, Any], output_file: Optional[str] = None, format: str = 'csv') -> List[str]:
        if not isinstance(export_result, dict) or 'data' not in export_result:
            raise ValueError("Invalid export result format")
        export_data = export_result.get('data', {})
        attributes = export_data.get('attributes', {})
        status = attributes.get('status', '').lower()
        if status not in ('complete', 'finished'):
            raise ValueError(f"Export is not ready for download. Current status: {status}")
        export_id = export_data.get('id')
        if not export_id:
            raise ValueError("No export ID found in export result")

        # Collect all result URLs if present; otherwise use single download endpoint
        result_urls: List[str] = []
        results = attributes.get('results')
        if isinstance(results, list) and results:
            for item in results:
                if isinstance(item, dict) and 'url' in item:
                    result_urls.append(item['url'])
        if not result_urls:
            # fallback to endpoint URL
            endpoint_url = attributes.get('download_url') or f"{self.base_url}{self.GROUP_EXPORT_DOWNLOAD_PATH.format(group_id=group_id, export_id=export_id)}?version={self.API_VERSION}"
            result_urls = [endpoint_url]

        # Ensure base filename and dated output directory
        if not output_file:
            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            output_file = f"snyk_group_export_{export_id}_{timestamp}.{format}"
        folder_timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        output_dir = os.path.join("exports", folder_timestamp)
        os.makedirs(output_dir, exist_ok=True)

        # Download all parts
        saved_files: List[str] = []
        for idx, url in enumerate(result_urls, start=1):
            part_suffix = f"_part{idx}" if len(result_urls) > 1 else ""
            base, ext = os.path.splitext(os.path.basename(output_file))
            out_path = os.path.join(output_dir, f"{base}{part_suffix}{ext}")
            console.print(f"[dim]Downloading part {idx}/{len(result_urls)}: {url}")
            try:
                with requests.get(url, headers=self.headers, stream=True, timeout=60) as r:
                    r.raise_for_status()
                    total_size = int(r.headers.get('content-length', 0))
                    downloaded_size = 0
                    with open(out_path, 'wb') as f:
                        for chunk in r.iter_content(chunk_size=8192):
                            if chunk:
                                f.write(chunk)
                                downloaded_size += len(chunk)
                                if total_size > 0:
                                    progress = (downloaded_size / total_size) * 100
                                    console.print(f"[dim]Downloading ({idx}): {progress:.1f}% ({downloaded_size}/{total_size} bytes)", end="\r")
                if os.path.getsize(out_path) == 0:
                    raise ValueError("Downloaded file is empty")
                saved_files.append(out_path)
                console.print(f"\n[green]✓ Saved: {out_path}")
            except requests.exceptions.HTTPError:
                # Fallback only for single endpoint case
                if len(result_urls) == 1:
                    fallback = f"{self.base_url}/groups/{group_id}/jobs/export/{export_id}/download?version={self.API_VERSION}"
                    console.print(f"[yellow]Download failed. Retrying via jobs path: {fallback}")
                    with requests.get(fallback, headers=self.headers, stream=True, timeout=60) as r:
                        r.raise_for_status()
                        with open(out_path, 'wb') as f:
                            for chunk in r.iter_content(chunk_size=8192):
                                if chunk:
                                    f.write(chunk)
                    if os.path.getsize(out_path) == 0:
                        raise ValueError("Downloaded file is empty")
                    saved_files.append(out_path)
                    console.print(f"\n[green]✓ Saved: {out_path}")
                else:
                    raise

        return saved_files
    
    def start_group_export_workflow(
        self,
        group_id: str,
        group_name: str = "unknown",
        columns: Optional[List[str]] = None,
        filters: Optional[Dict[str, Any]] = None,
    ) -> List[str]:
        if not group_id:
            raise ValueError("Group ID is required")

        downloaded_files: List[str] = []
        safe_group_name = "".join(c if c.isalnum() else "_" for c in group_name)

        try:
            export_format = self.get_user_input("Export format (json/csv)", "csv").lower()
            if export_format not in ["csv", "json"]:
                console.print("[yellow]Invalid format. Defaulting to CSV.[/]")
                export_format = "csv"

            # Build default filters if none provided
            user_filters = filters
            if user_filters is None:
                orgs = self.list_organizations(group_id)
                org_ids = [org.get('id') for org in orgs if org.get('id')]
                user_filters = {"orgs": org_ids} if org_ids else {}

            # Ensure we have date filters (required by Snyk group export API)
            user_filters = dict(user_filters) if user_filters else {}
            date_filters: Dict[str, Any] = {}

            def _normalize_datetime_input(raw: str, is_end: bool = False) -> Optional[str]:
                if not raw:
                    return None
                raw = raw.strip()
                if not raw:
                    return None
                try:
                    dt = datetime.strptime(raw, "%Y-%m-%dT%H:%M:%SZ")
                except ValueError:
                    try:
                        dt = datetime.strptime(raw, "%Y-%m-%d")
                        if is_end:
                            dt = dt + timedelta(days=1) - timedelta(seconds=1)
                    except ValueError:
                        console.print(
                            f"[yellow]Invalid date format '{raw}'. Expected YYYY-MM-DD or YYYY-MM-DDTHH:MM:SSZ."
                        )
                        return None
                dt = dt.replace(tzinfo=timezone.utc)
                return dt.strftime("%Y-%m-%dT%H:%M:%SZ")

            if Confirm.ask("Do you want to enter a custom date range?"):
                console.print("[dim]Leave inputs blank to skip a particular bound.")
                introduced_from_raw = self.get_user_input(
                    "Introduced from (YYYY-MM-DD or YYYY-MM-DDTHH:MM:SSZ)", ""
                )
                introduced_to_raw = self.get_user_input(
                    "Introduced to (YYYY-MM-DD or YYYY-MM-DDTHH:MM:SSZ)", ""
                )
                updated_from_raw = self.get_user_input(
                    "Updated from (YYYY-MM-DD or YYYY-MM-DDTHH:MM:SSZ)", ""
                )
                updated_to_raw = self.get_user_input(
                    "Updated to (YYYY-MM-DD or YYYY-MM-DDTHH:MM:SSZ)", ""
                )

                introduced_filter: Dict[str, str] = {}
                intro_from_norm = _normalize_datetime_input(introduced_from_raw, is_end=False)
                intro_to_norm = _normalize_datetime_input(introduced_to_raw, is_end=True)
                if intro_from_norm:
                    introduced_filter["from"] = intro_from_norm
                if intro_to_norm:
                    introduced_filter["to"] = intro_to_norm
                if introduced_filter:
                    date_filters["introduced"] = introduced_filter

                updated_filter: Dict[str, str] = {}
                updated_from_norm = _normalize_datetime_input(updated_from_raw, is_end=False)
                updated_to_norm = _normalize_datetime_input(updated_to_raw, is_end=True)
                if updated_from_norm:
                    updated_filter["from"] = updated_from_norm
                if updated_to_norm:
                    updated_filter["to"] = updated_to_norm
                if updated_filter:
                    date_filters["updated"] = updated_filter

                if not date_filters:
                    console.print("[yellow]No valid date bounds entered. Using default last 30 days.")

            if not date_filters:
                end_date = datetime.utcnow().replace(tzinfo=timezone.utc)
                start_date = end_date - timedelta(days=30)
                date_filters["introduced"] = {
                    "from": start_date.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "to": end_date.strftime("%Y-%m-%dT%H:%M:%SZ"),
                }
                console.print(
                    f"[dim]Using introduced date range {date_filters['introduced']['from']} to {date_filters['introduced']['to']}"
                )

            user_filters.update(date_filters)

            datasets: List[str] = ["issues", "usage"]

            for dataset in datasets:
                try:
                    console.print(f"\n[bold]Exporting {dataset} for group {group_name} (ID: {group_id})...")
                    with console.status(f"[bold green]Exporting {dataset} for {group_name}..."):
                        filters_payload = json.loads(json.dumps(user_filters)) if user_filters else {}
                        export_result = self.start_group_export(
                            group_id=group_id,
                            dataset=dataset,
                            columns=columns,
                            filters=filters_payload,
                            formats=[export_format],
                        )

                        data = export_result.get("data", {})
                        export_id = data.get("id")
                        if not export_id:
                            console.print(f"[red]Failed to start {dataset} group export.")
                            continue

                        console.print(f"[green]{dataset.capitalize()} group export started with ID: {export_id}")
                        try:
                            console.print(Panel(json.dumps(export_result, indent=2), title=f"{dataset} group export response"))
                        except (TypeError, ValueError):
                            console.print(f"[dim]Raw export response: {export_result}")

                        max_attempts = 60
                        attempts = 0

                        while attempts < max_attempts:
                            status = self.get_group_export_status(group_id, export_id)
                            if status and "data" in status:
                                attrs = status["data"].get("attributes", {})
                                export_status = attrs.get("status", "unknown")
                                if isinstance(export_status, str):
                                    export_status = export_status.lower()

                                if export_status in ("complete", "finished"):
                                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                                    output_file = f"snyk_group_export_{safe_group_name}_{group_id[:8]}_{dataset}_{timestamp}.{export_format}"
                                    files = self.download_group_export(
                                        group_id,
                                        status,
                                        output_file=output_file,
                                        format=export_format,
                                    )
                                    self.enrich_export_files(files)
                                    downloaded_files.extend(files)
                                    break

                                if export_status in ("failed", "cancelled"):
                                    console.print(f"[red]{dataset.capitalize()} group export {export_status}.")
                                    break

                                console.print(
                                    f"[yellow]{dataset.capitalize()} group export status: {export_status} "
                                    f"(attempt {attempts + 1}/{max_attempts})"
                                )
                                time.sleep(5)
                                attempts += 1
                            else:
                                console.print("[red]Failed to get group export status.")
                                break

                        if attempts >= max_attempts:
                            console.print(f"[red]Timeout waiting for {dataset} group export to complete.")

                except Exception as e:
                    console.print(f"[red]Error during {dataset} group export: {e}")
                    import traceback
                    traceback.print_exc()

        except Exception as e:
            console.print(f"\n[red]Error during group export: {e}")
            import traceback
            traceback.print_exc()

        # Combine files if multiple datasets were exported
        if len(downloaded_files) > 1:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            combined_file = f"exports/{timestamp}/snyk_combined_group_export_{group_id[:8]}_{timestamp}.csv"
            if self.combine_csv_files(downloaded_files, combined_file):
                console.print(f"[green]✓ Combined export saved to: {combined_file}")
                console.print(f"[dim]Combined file name: {combined_file}")

        # Fetch and save project data
        project_files = []
        for org in self.list_organizations(group_id):
            org_id = org.get('id')
            if org_id:
                try:
                    projects = self.get_org_projects(org_id)
                    for project in projects:
                        project_id = project.get('id')
                        if project_id:
                            project_data = self.get_project_v1(org_id, project_id)
                            if project_data:
                                project_csv = f"exports/{timestamp}/snyk_project_{project_id}_{timestamp}.csv"
                                self.save_project_to_csv(project_data, project_csv)
                                project_files.append(project_csv)
                                console.print(f"[green]✓ Project data saved to: {project_csv}")
                except Exception as e:
                    console.print(f"[red]Error fetching project data: {e}")

        # Combine all files including project data
        all_files = downloaded_files + project_files
        if len(all_files) > 1:
            final_combined_file = f"exports/{timestamp}/snyk_final_combined_export_{group_id[:8]}_{timestamp}.csv"
            if self.combine_csv_files(all_files, final_combined_file):
                console.print(f"[green]✓ Final combined export saved to: {final_combined_file}")
                console.print(f"[dim]Final combined file name: {final_combined_file}")

        return downloaded_files

    def log_export_summary(self, export_type: str, org_id: str, files: List[str]) -> None:
        """Log a summary of the export operation."""
        console.print(f"\n[green]Export Summary for {export_type} in {org_id}:")
        console.print(f"Files downloaded: {len(files)}")
        for file in files:
            console.print(f"  - {file}")
        console.print(f"[dim]Enrichment applied: Project metadata and policy ignores added.[/]")
    
    def list_groups(self) -> List[Dict[str, Any]]:
        """List all organizations (which function as groups) accessible with the current API token.
        
        Returns:
            List of organization/group dictionaries with id, name, and other attributes
        """
        try:
            # Get all organizations the user has access to
            orgs_url = f"{self.base_url}/orgs?version={self.API_VERSION}"
            response = requests.get(orgs_url, headers=self.headers)
            response.raise_for_status()
            orgs_data = response.json()
            
            # Transform the response to ensure consistent structure
            groups = []
            excluded_ids = {
                "a8b06ecd-d0db-4a12-941d-c00691975a90",
                "788993e3-0241-4cc7-885d-4789d2a41ec5",
                "48ad8276-fee9-456b-a935-d75cc0ba063f",
                "c0aa30b3-2123-46f3-8171-1c2953485c32",
                "c655dde1-2a73-4f76-89b0-b7e7f0ae2dcd",
                "8c6a7f7d-a46b-4d6a-98ee-5b44ff992519",
                "8b9466b4-1f85-4fef-bf73-3b44184082fa",
                "e7f5d5d2-f25d-45be-b9f7-58cb0b74aad7",
                "26983627-fe27-4e94-bf8f-0050874cda60",
                "492c82c0-8300-445d-9a64-7ce90cdc03db"
            }
            for org in orgs_data.get('data', []):
                org_id = org.get('id')
                if org_id not in excluded_ids:
                    attrs = org.get('attributes', {})
                    groups.append({
                        'id': org_id,
                        'name': attrs.get('name', 'Unnamed Organization'),
                        'type': 'organization',
                        'attributes': attrs
                    })
                
            if not groups:
                console.print("[yellow]No organizations found for the current user.[/]")
                
            return groups
            
        except requests.exceptions.RequestException as e:
            error_msg = str(e)
            if hasattr(e, 'response') and e.response is not None:
                try:
                    error_detail = e.response.json()
                    error_msg = f"{error_msg} - {json.dumps(error_detail, indent=2)}"
                except:
                    error_msg = f"{error_msg} - {e.response.text}"
            console.print(f"[red]Error fetching organizations: {error_msg}")
            return []

    def list_organizations(self, group_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """List all organizations accessible with the current API token.
        
        In this implementation, we treat organizations as groups since that's how they're structured.
        
        Args:
            group_id: Optional group ID to filter organizations by group
            
        Returns:
            List of organization dictionaries with id, name, and other attributes
        """
        try:
            # If a group_id is provided, try the group orgs endpoint first
            if group_id:
                try:
                    grp_url = f"{self.base_url}/groups/{group_id}/orgs?version={self.API_VERSION}"
                    r = requests.get(grp_url, headers=self.headers)
                    if r.status_code == 200:
                        data = r.json()
                        orgs: List[Dict[str, Any]] = []
                        for org in data.get('data', []):
                            attrs = org.get('attributes', {})
                            orgs.append({
                                'id': org.get('id'),
                                'name': attrs.get('name', 'Unnamed Organization'),
                                'type': 'organization',
                                'attributes': attrs,
                                'group_id': group_id,
                            })
                        return orgs
                except requests.exceptions.RequestException:
                    pass  # Fall back to global listing

            # Global listing of organizations
            orgs_url = f"{self.base_url}/orgs?version={self.API_VERSION}"
            response = requests.get(orgs_url, headers=self.headers)
            response.raise_for_status()
            orgs_data = response.json()

            # Transform the response to ensure consistent structure
            results: List[Dict[str, Any]] = []
            for org in orgs_data.get('data', []):
                attrs = org.get('attributes', {})
                org_item = {
                    'id': org.get('id'),
                    'name': attrs.get('name', 'Unnamed Organization'),
                    'type': 'organization',
                    'attributes': attrs
                }
                # If specific group_id was requested, try to match by attributes.group_id
                if group_id:
                    if attrs.get('group_id') == group_id:
                        results.append(org_item)
                else:
                    results.append(org_item)

            if group_id and not results:
                # As a last resort, if group_id was actually an org id, include it
                for org in orgs_data.get('data', []):
                    if org.get('id') == group_id:
                        attrs = org.get('attributes', {})
                        results.append({
                            'id': org.get('id'),
                            'name': attrs.get('name', 'Unnamed Organization'),
                            'type': 'organization',
                            'attributes': attrs
                        })

            if not results:
                console.print("[yellow]No organizations found for the current user.[/]")

            return results

        except requests.exceptions.RequestException as e:
            error_msg = str(e)
            if hasattr(e, 'response') and e.response is not None:
                try:
                    error_detail = e.response.json()
                    error_msg = f"{error_msg} - {json.dumps(error_detail, indent=2)}"
                except:
                    error_msg = f"{error_msg} - {e.response.text}"
            console.print(f"[red]Error fetching organizations: {error_msg}")
            return []
    
    def _validate_date_format(self, date_str: str) -> bool:
        """Validate that a date string is in the correct format (YYYY-MM-DDTHH:MM:SSZ)."""
        try:
            datetime.strptime(date_str, '%Y-%m-%dT%H:%M:%SZ')
            return True
        except ValueError:
            try:
                # Also allow date-only format
                datetime.strptime(date_str, '%Y-%m-%d')
                return True
            except ValueError:
                return False

    def start_export(
        self,
        export_type: str = "issues",
        org_id: Optional[str] = None,
        columns: Optional[List[str]] = None,
        dataset: str = "issues",
        # Filter parameters
        environment: Optional[List[str]] = None,
        introduced_from: Optional[str] = None,
        introduced_to: Optional[str] = None,
        lifecycle: Optional[List[str]] = None,
        updated_from: Optional[str] = None,
        updated_to: Optional[str] = None,
        orgs: Optional[List[str]] = None,
        severity: Optional[List[str]] = None,
        issue_type: Optional[List[str]] = None,
        issue_status: Optional[List[str]] = None,
        project_id: Optional[List[str]] = None,
        project_name: Optional[List[str]] = None,
        project_source: Optional[List[str]] = None,
        schema: Optional[str] = None,
        formats: List[str] = ["csv"]
    ) -> Dict[str, Any]:
        """Start a new export job with the specified parameters using the Snyk REST API.
        
        Args:
            export_type: Type of export ('issues' or 'dependencies')
            org_id: Organization ID (uses instance org_id if not provided)
            columns: List of columns to include in the export (not used in v2024-06-21~beta)
            dataset: The dataset to export (default: 'issues')
            
            # Filter parameters
            environment: Filter by environment (e.g., ['BACKEND', 'EXTERNAL'])
            introduced_from: Filter issues introduced from this date (YYYY-MM-DD or YYYY-MM-DDTHH:MM:SSZ)
            introduced_to: Filter issues introduced to this date (YYYY-MM-DD or YYYY-MM-DDTHH:MM:SSZ)
            lifecycle: Filter by lifecycle (e.g., ['PRODUCTION', 'DEVELOPMENT'])
            updated_from: Filter issues updated from this date (YYYY-MM-DD or YYYY-MM-DDTHH:MM:SSZ)
            updated_to: Filter issues updated to this date (YYYY-MM-DD or YYYY-MM-DDTHH:MM:SSZ)
            orgs: Filter by organization IDs (for group exports)
            severity: Filter by severity (e.g., ['critical', 'high', 'medium', 'low'])
            issue_type: Filter by issue type (e.g., ['vuln', 'license', 'configuration'])
            issue_status: Filter by issue status (e.g., ['open', 'resolved', 'ignored'])
            project_id: Filter by project IDs
            project_name: Filter by project names
            project_source: Filter by project source (e.g., ['github', 'gitlab', 'cli'])
            schema: Schema version to use (default: '2024-06-21~beta')
            formats: List of export formats (default: ['csv'])
            
        Returns:
            Dict containing the export job details
            
        Raises:
            ValueError: If required parameters are missing or invalid
            requests.exceptions.RequestException: If the API request fails
        """
        # Use instance org_id if not provided
        org_id = org_id or self.org_id
        if not org_id:
            raise ValueError("Organization ID is required")
            
        # Set default schema if not provided
        schema = schema or "2024-06-21~beta"
            
        # Build filters dictionary
        filters: Dict[str, Any] = {}
        
        # Add simple filters
        for filter_name, filter_value in [
            ("environment", environment),
            ("lifecycle", lifecycle),
            ("orgs", orgs),
            ("severity", severity),
            ("issue_type", issue_type),
            ("issue_status", issue_status),
            ("project_id", project_id),
            ("project_name", project_name),
            ("project_source", project_source)
        ]:
            if filter_value:
                filters[filter_name] = filter_value
        
        # Add date range filters
        for range_name, from_date, to_date in [
            ("introduced", introduced_from, introduced_to),
            ("updated", updated_from, updated_to)
        ]:
            if from_date or to_date:
                filters[range_name] = {}
                if from_date:
                    filters[range_name]["from"] = from_date
                if to_date:
                    filters[range_name]["to"] = to_date

        # Build the request payload for Exports API
        exports_payload: Dict[str, Any] = {
            "data": {
                "type": "export",
                "attributes": {
                    "dataset": export_type,  # "issues" | "dependencies"
                    "format": (formats[0] if formats else "csv").lower(),
                    "filters": filters
                }
            }
        }

        # Legacy report payload fallback
        report_payload: Dict[str, Any] = {
            "data": {
                "type": "report",
                "attributes": {
                    "report_type": export_type,
                    "format": (formats[0] if formats else "csv").lower(),
                    "filters": filters
                }
            }
        }

        # Set up headers with API version and authentication
        headers = {
            "Content-Type": "application/vnd.api+json",
            "Accept": "application/vnd.api+json",
            "Authorization": f"token {self.api_token}",
            "Snyk-Request-Id": str(uuid.uuid4()),
            "Snyk-Version": self.API_VERSION
        }

        try:
            # Use generic exports endpoint for all datasets; keep legacy fallback paths
            primary_path = self.EXPORT_PATH.format(org_id=org_id)
            if export_type == "issues":
                legacy_path = f"/orgs/{org_id}/issues/report"
            elif export_type == "usage":
                legacy_path = f"/orgs/{org_id}/usage/report"
            else:
                legacy_path = f"/orgs/{org_id}/issues/report"

            # Try new exports endpoint first
            url = f"{self.base_url}{primary_path}?version={self.API_VERSION}"
            console.print(f"[dim]Starting export via: {url}")
            response = requests.post(url, json=exports_payload, headers=headers)
            try:
                response.raise_for_status()
            except requests.exceptions.HTTPError as he:
                # Fallback to legacy version if 404 Not Found
                if response is not None and response.status_code in (404, 400):
                    legacy_version = "2024-06-21~beta"
                    fallback_headers = headers.copy()
                    fallback_headers["Snyk-Version"] = legacy_version
                    fallback_url = f"{self.base_url}{legacy_path}?version={legacy_version}"
                    console.print(f"[yellow]Exports endpoint failed ({response.status_code}). Retrying via legacy endpoint: {fallback_url}")
                    response = requests.post(fallback_url, json=report_payload, headers=fallback_headers)
                    response.raise_for_status()
                else:
                    raise

            # Parse the response
            response_data = response.json()

            # Validate response format
            if not isinstance(response_data, dict):
                raise ValueError("Invalid response format from Snyk API")

            # Add metadata to the response
            response_data["export_metadata"] = {
                "requested_at": datetime.utcnow().isoformat() + "Z",
                "dataset": dataset,
                "filters": filters,
                "columns": columns
            }

            return response_data

        except requests.exceptions.RequestException as e:
            # Enhanced error handling with detailed error messages
            error_msg = f"Error starting export: {str(e)}"
            if hasattr(e, 'response') and e.response is not None:
                try:
                    error_data = e.response.json()
                    error_msg += f"\nStatus Code: {e.response.status_code}"
                    if "errors" in error_data:
                        error_msg += f"\nErrors: {error_data['errors']}"
                    elif "message" in error_data:
                        error_msg += f"\nMessage: {error_data['message']}"
                except ValueError:
                    error_msg += f"\nResponse: {e.response.text}"
            raise Exception(error_msg) from e

    def get_export_status(self, export_id: str, org_id: Optional[str] = None, dataset: str = "issues") -> Dict[str, Any]:
        """Get the status of an export job using the Snyk REST API.
        
        Args:
            export_id: The ID of the export job to check
            org_id: Organization ID (uses instance org_id if not provided)
            
        Returns:
            Dict containing the export status and metadata
            
        Raises:
            ValueError: If required parameters are missing or invalid
            requests.exceptions.RequestException: If the API request fails
        """
        org_id = org_id or self.org_id
        if not org_id:
            raise ValueError("Organization ID is required")
            
        # Use generic exports status path; fallback to legacy report status
        primary = self.EXPORT_STATUS_PATH.format(org_id=org_id, export_id=export_id)
        if dataset == "usage":
            legacy = f"/orgs/{org_id}/usage/report/status/{export_id}"
        else:
            legacy = f"/orgs/{org_id}/issues/report/status/{export_id}"

        url = f"{self.base_url}{primary}?version={self.API_VERSION}"
        
        try:
            console.print(f"[dim]Checking export status: {url}")
            response = requests.get(url, headers=self.headers)
            try:
                response.raise_for_status()
            except requests.exceptions.HTTPError as he:
                if response is not None and response.status_code in (404, 400):
                    legacy_url = f"{self.base_url}{legacy}?version=2024-06-21~beta"
                    console.print(f"[yellow]Status endpoint fallback: {legacy_url}")
                    response = requests.get(legacy_url, headers=self.headers)
                    response.raise_for_status()
                else:
                    raise
            
            # Parse the response
            status_data = response.json()
            
            # Log the status for debugging
            console.print(f"[dim]Export status: {status_data}")
            
            # Validate response format
            if not isinstance(status_data, dict) or 'data' not in status_data:
                raise ValueError("Invalid response format from Snyk API")
                
            return status_data
            
        except requests.exceptions.RequestException as e:
            error_msg = str(e)
            if hasattr(e, 'response') and e.response is not None:
                try:
                    error_detail = e.response.json()
                    error_msg = f"{error_msg} - {json.dumps(error_detail, indent=2)}"
                except Exception as json_err:
                    error_msg = f"{error_msg} - {e.response.text}"
            console.print(f"[red]Error getting export status: {error_msg}")
            raise requests.exceptions.RequestException(f"Failed to get export status: {error_msg}")

    def download_export(self, export_result: Dict[str, Any], output_file: str = None, format: str = 'csv') -> Optional[str]:
        """Download the export file from a completed export job using the Snyk REST API.
        
        Args:
            export_result: The export job result from start_export() or get_export_status()
            output_file: Optional output file path (default: auto-generate)
            format: Export format (default: 'csv')
            
        Returns:
            Path to the downloaded file, or None if download failed
            
        Raises:
            ValueError: If the export is not in a downloadable state
            requests.exceptions.RequestException: If the download fails
        """
        # Extract the export data from the result
        if not isinstance(export_result, dict) or 'data' not in export_result:
            raise ValueError("Invalid export result format")
            
        export_data = export_result.get('data', {})
        attributes = export_data.get('attributes', {})
        
        # Check if the export is ready for download
        status = attributes.get('status', '').lower()
        if status != 'complete':
            raise ValueError(f"Export is not ready for download. Current status: {status}")
        
        # Get the organization ID from the export data or use the instance org_id
        org_id = None
        if 'relationships' in export_data:
            org_id = export_data.get('relationships', {}).get('org', {}).get('data', {}).get('id')
        
        # If org_id is still not found, try to get it from the instance
        if not org_id and hasattr(self, 'org_id'):
            org_id = self.org_id
        
        # Get the export ID
        export_id = export_data.get('id')
        if not export_id:
            raise ValueError("No export ID found in export result")
        
        # Construct the download URL
        if not org_id:
            raise ValueError("Organization ID is required but not found in export result or instance")
        
        # Prefer direct download URL in response if present
        download_url = attributes.get('download_url')
        if not download_url:
            # Use generic export download; fallback to legacy report download by dataset
            dataset = attributes.get('dataset', 'issues')
            primary = self.EXPORT_DOWNLOAD_PATH.format(org_id=org_id, export_id=export_id)
            if dataset == 'usage':
                legacy = f"/orgs/{org_id}/usage/report/download/{export_id}"
            else:
                legacy = f"/orgs/{org_id}/issues/report/download/{export_id}"

            download_url = f"{self.base_url}{primary}?version={self.API_VERSION}"
        
        # Debug information
        console.print(f"[dim]Using download URL: {download_url}")
                
        # Auto-generate output filename if not provided
        if not output_file:
            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            export_id = export_data.get('id', 'export')
            output_file = f"snyk_export_{export_id}_{timestamp}.{format}"
            
        try:
            # Add retry logic for the download
            max_retries = 3
            retry_delay = 5  # seconds
            
            for attempt in range(1, max_retries + 1):
                try:
                    console.print(f"[dim]Downloading export (attempt {attempt}/{max_retries})...")
                    
                    # Stream the download to handle large files
                    with requests.get(download_url, headers=self.headers, stream=True, timeout=30) as r:
                        r.raise_for_status()
                        
                        # Get total file size for progress tracking
                        total_size = int(r.headers.get('content-length', 0))
                        downloaded_size = 0
                        
                        # Save the file with progress tracking
                        with open(output_file, 'wb') as f:
                            for chunk in r.iter_content(chunk_size=8192):
                                if chunk:  # Filter out keep-alive new chunks
                                    f.write(chunk)
                                    downloaded_size += len(chunk)
                                    # Show progress if we know the total size
                                    if total_size > 0:
                                        progress = (downloaded_size / total_size) * 100
                                        console.print(f"[dim]Downloading: {progress:.1f}% ({downloaded_size}/{total_size} bytes)", end="\r")
                        
                        # Verify the downloaded file has content
                        if os.path.getsize(output_file) == 0:
                            raise ValueError("Downloaded file is empty")
                            
                        console.print(f"\n[green]✓ Export downloaded successfully to: {output_file}")
                        return output_file
                        
                except (requests.exceptions.RequestException, IOError) as e:
                    if attempt == max_retries:
                        raise  # Re-raise on last attempt
                        
                    console.print(f"[yellow]Attempt {attempt} failed: {str(e)}")
                    console.print(f"[dim]Retrying in {retry_delay} seconds...")
                    time.sleep(retry_delay)
                
        except requests.exceptions.RequestException as e:
            error_msg = str(e)
            if hasattr(e, 'response') and e.response is not None:
                try:
                    error_detail = e.response.json()
                    error_msg = f"{error_msg} - {json.dumps(error_detail, indent=2)}"
                except Exception as json_err:
                    error_msg = f"{error_msg} - {e.response.text}"
            console.print(f"[red]Error downloading export: {error_msg}")
            raise requests.exceptions.RequestException(f"Failed to download export: {error_msg}")

    def combine_csv_files(self, input_files: List[str], output_file: str) -> bool:
        """Combine multiple CSV files into a single CSV file.
        
        Args:
            input_files: List of input CSV file paths
            output_file: Path to the output combined CSV file
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # Read all CSV files into a list of DataFrames
            dfs = []
            for file in input_files:
                if not os.path.exists(file):
                    console.print(f"[yellow]Warning: File not found: {file}")
                    continue
                try:
                    df = pd.read_csv(file)
                    dfs.append(df)
                except Exception as e:
                    console.print(f"[red]Error reading {file}: {str(e)}")
                    continue
            
            if not dfs:
                console.print("[red]No valid CSV files to combine")
                return False
            
            # Concatenate all DataFrames
            combined_df = pd.concat(dfs, ignore_index=True)
            
            # Remove duplicate rows based on PROJECT_PUBLIC_ID
            initial_count = len(combined_df)
            if 'PROJECT_PUBLIC_ID' in combined_df.columns:
                combined_df = combined_df.drop_duplicates(subset=['PROJECT_PUBLIC_ID'], keep='first')
            else:
                combined_df = combined_df.drop_duplicates()
            removed_count = initial_count - len(combined_df)
            
            # Ensure the directory exists
            output_dir = os.path.dirname(output_file)
            os.makedirs(output_dir, exist_ok=True)
            
            # Save the combined DataFrame to a new CSV file
            combined_df.to_csv(output_file, index=False, quoting=csv.QUOTE_NONNUMERIC)
            
            console.print(f"[green]Combined {len(dfs)} files into {output_file}")
            if removed_count > 0:
                console.print(f"[yellow]Removed {removed_count} duplicate rows based on PROJECT_PUBLIC_ID")
                
            return True
            
        except Exception as e:
            console.print(f"[red]Error combining CSV files: {e}")
            return False
    
    def combine_json_files(self, input_files: List[str], output_file: str) -> bool:
        """
        Combine multiple JSON files into a single JSON array.
        If an input JSON is already a list, extend; if it's a dict, append as an element.

        Args:
            input_files: List of JSON file paths to combine.
            output_file: Destination JSON file path.

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            combined: List[Any] = []
            for file in input_files:
                if not os.path.exists(file):
                    console.print(f"[yellow]Warning: File not found: {file}")
                    continue
                try:
                    with open(file, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                        if isinstance(data, list):
                            combined.extend(data)
                        else:
                            combined.append(data)
                except Exception as e:
                    console.print(f"[red]Error reading {file}: {str(e)}")
                    continue

            if not combined:
                console.print("[red]No valid JSON content to combine")
                return False

            with open(output_file, 'w', encoding='utf-8') as out:
                json.dump(combined, out, ensure_ascii=False, indent=2)

            console.print(f"[green]Combined JSON written to {output_file}")
            return True
        except Exception as e:
            console.print(f"[red]Error combining JSON files: {e}")
            return False

    def start_export_workflow(self, org_id: str, org_name: str = "unknown") -> List[str]:
        """Start an export workflow for a single organization.
        
        Args:
            org_id: Organization ID to export data from
            org_name: Organization name for display purposes
            
        Returns:
            List of paths to downloaded export files
        """
        downloaded_files = []
        safe_org_name = "".join(c if c.isalnum() else "_" for c in org_name)
        
        try:
            # Get export format
            export_format = self.get_user_input("Export format (json/csv)", "csv").lower()
            if export_format not in ['json', 'csv']:
                console.print("[yellow]Invalid format. Defaulting to CSV.[/]")
                export_format = 'csv'
            
            # Export both issues and dependencies
            for dataset in ["issues", "dependencies"]:
                try:
                    console.print(f"\n[bold]Exporting {dataset} for {org_name} (ID: {org_id})...")
                    
                    # Start the export
                    with console.status(f"[bold green]Exporting {dataset} for {org_name}..."):
                        export_result = self.start_export(
                            export_type=dataset,
                            org_id=org_id,
                            formats=[export_format]
                        )
                        
                        if not export_result or 'data' not in export_result or 'id' not in export_result['data']:
                            console.print(f"[red]Failed to start {dataset} export.")
                            continue
                            
                        export_id = export_result['data']['id']
                        console.print(f"[green]{dataset.capitalize()} export started with ID: {export_id}")
                        
                        # Check status periodically
                        max_attempts = 60  # 5 minutes max wait (5s * 60 = 300s = 5min)
                        attempts = 0
                        
                        while attempts < max_attempts:
                            status = self.get_export_status(export_id, org_id)
                            if status and "data" in status:
                                export_status = status["data"].get("status", "unknown").lower()

                                if export_status == "complete":
                                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                                    output_file = f"snyk_export_{safe_org_name}_{org_id[:8]}_{dataset}_{timestamp}.{export_format}"
                                    
                                    downloaded_file = self.download_export(
                                        status, output_file, export_format
                                    )
                                    if downloaded_file:
                                        console.print(f"[green]✓ {dataset.capitalize()} export saved to: {downloaded_file}")
                                        downloaded_files.append(downloaded_file)
                                        self.enrich_export_files([downloaded_file])
                                    break

                                elif export_status in ["failed", "cancelled"]:
                                    console.print(f"[red]{dataset.capitalize()} export {export_status}.")
                                    break
                                    
                                # Show progress
                                console.print(f"[yellow]{dataset.capitalize()} export status: {export_status} (attempt {attempts + 1}/{max_attempts})")
                                time.sleep(5)
                                attempts += 1
                            else:
                                console.print("[red]Failed to get export status.")
                                break
                                
                        if attempts >= max_attempts:
                            console.print(f"[red]Timeout waiting for {dataset} export to complete.")

                except Exception as e:
                    console.print(f"[red]Error during {dataset} export: {e}")
                    import traceback
                    traceback.print_exc()

        except Exception as e:
            console.print(f"\n[red]Error during export: {e}")
            import traceback
            traceback.print_exc()

        self.log_export_summary("Single Organization Export", org_id, downloaded_files)
        return downloaded_files

    def log_export_summary(self, export_type: str, org_id: str, files: List[str]) -> None:
        """Log a summary of the export operation."""
        console.print(f"\n[green]Export Summary for {export_type} in {org_id}:")
        console.print(f"Files downloaded: {len(files)}")
        for file in files:
            console.print(f"  - {file}")
        console.print(f"[dim]Enrichment applied: Project metadata and policy ignores added.[/]")

    @staticmethod
    def get_user_input(prompt: str, default: Optional[str] = None) -> str:
        """
        Helper function to get user input with a default value.

        Args:
            prompt: The prompt to display to the user.
            default: Default value if user enters nothing.

        Returns:
            User input or default value.
        """
        try:
            if default is not None:
                user_input = input(f"{prompt} [{default}]: ").strip()
                return user_input if user_input else default
            return input(f"{prompt}: ").strip()
        except (EOFError, KeyboardInterrupt):
            console.print("\n[yellow]Operation cancelled by user.")
            sys.exit(0)
    def get_org_projects(self, org_id: str) -> List[Dict[str, Any]]:
        """Get all projects for an organization using the Snyk v1 API."""
        try:
            url = f"{self.V1_BASE}/org/{org_id}/projects"
            response = requests.get(url, headers=self.headers_v1, timeout=30)
            if response.status_code == 410:
                console.print(f"[yellow]Organization {org_id} is gone or inaccessible.")
                return []
            response.raise_for_status()
            data = response.json()
            return data.get('projects', [])
        except requests.exceptions.RequestException as e:
            console.print(f"[red]Error fetching projects for org {org_id}: {e}")
            return []

    def save_project_to_csv(self, project_data: Dict[str, Any], output_file: str) -> None:
        """Save project data to a CSV file."""
        try:
            df = pd.DataFrame([project_data])
            df.to_csv(output_file, index=False)
        except Exception as e:
            console.print(f"[red]Error saving project data to CSV: {e}")
    def get_project_last_tested_date(self, org_id: str, project_id: str) -> Optional[str]:
        """Retrieve the last tested date for a specific project.

        Args:
            org_id: Organization ID
            project_id: Project ID

        Returns:
            The last tested date as a string, or None if an error occurs
        """
        url = f"{self.V1_BASE}/org/{org_id}/project/{project_id}"
        try:
            response = requests.get(url, headers=self.headers_v1, timeout=30)
            response.raise_for_status()
            data = response.json()
            last_tested_date = data.get("lastTestedDate")
            console.print(f"[green]Last tested date for project {project_id}: {last_tested_date}")
            return last_tested_date
        except requests.exceptions.RequestException as e:
            console.print(f"[red]Error fetching project last tested date: {e}")
            return None
