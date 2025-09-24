#!/usr/bin/env python3
import os
import sys
import time
from datetime import datetime, timedelta
from typing import List

from rich.console import Console
from rich.prompt import Prompt, Confirm
from rich.table import Table

from snyk_export import SnykExportAPI
from build_xml import find_combined_csv, analyze_csv_structure, generate_xsd, write_xml_from_csv


console = Console()


def pick_region() -> str:
    console.print("\n[bold]Select Region[/]")
    console.print("1) US (https://api.snyk.io)")
    console.print("2) EU (https://api.eu.snyk.io)")
    sel = Prompt.ask("Enter 1 or 2", choices=["1", "2"], default="1")
    return "https://api.snyk.io/rest" if sel == "1" else "https://api.eu.snyk.io/rest"


def pick_dataset() -> List[str]:
    console.print("\n[bold]Datasets[/]")
    console.print("1) issues  2) usage  3) both")
    sel = Prompt.ask("Enter 1/2/3", choices=["1", "2", "3"], default="1")
    if sel == "1":
        return ["issues"]
    if sel == "2":
        return ["usage"]
    return ["issues", "usage"]


def build_filters() -> dict:
    console.print("\n[bold]Filters[/]")
    use_updated = Confirm.ask("Limit by updated window?", default=True)
    filters = {}
    if use_updated:
        days = int(Prompt.ask("How many days back?", default="30"))
        now = datetime.utcnow()
        filters["updated"] = {
            "from": (now - timedelta(days=days)).strftime("%Y-%m-%dT00:00:00Z"),
            "to": now.strftime("%Y-%m-%dT00:00:00Z"),
        }
    if Confirm.ask("Add introduced window (issues only)?", default=False):
        days = int(Prompt.ask("How many days back?", default="30"))
        now = datetime.utcnow()
        filters["introduced"] = {
            "from": (now - timedelta(days=days)).strftime("%Y-%m-%dT00:00:00Z"),
            "to": now.strftime("%Y-%m-%dT00:00:00Z"),
        }
    return filters


def run_group_export_flow() -> None:
    token = os.getenv("SNYK_API_TOKEN") or Prompt.ask("SNYK API token")
    os.environ["SNYK_API_TOKEN"] = token
    group_id = Prompt.ask("Group ID")
    base_url = pick_region()
    datasets = pick_dataset()
    export_format = Prompt.ask("Export format", choices=["csv", "json"], default="csv")
    poll_interval = int(Prompt.ask("Poll interval seconds", default="30"))
    timeout_sec = int(Prompt.ask("Timeout seconds", default="1800"))
    filters = build_filters()

    client = SnykExportAPI(token, base_url=base_url)

    downloaded: List[str] = []
    for dataset in datasets:
        console.print(f"\n[bold]Starting group export ({dataset})[/]")
        payload_columns = [
            "ISSUE_SEVERITY_RANK",
            "ISSUE_SEVERITY",
            "SCORE",
            "PROBLEM_TITLE",
            "CVE",
            "CWE",
            "PROJECT_NAME",
            "PROJECT_URL",
            "EXPLOIT_MATURITY",
            "AUTOFIXABLE",
            "FIRST_INTRODUCED",
            "PRODUCT_NAME",
            "ISSUE_URL",
            "ISSUE_STATUS_INDICATOR",
            "ISSUE_TYPE",
        ] if dataset == "issues" else [
            "ID", "ORG_PUBLIC_ID", "GROUP_PUBLIC_ID", "PRODUCT_DISPLAY_NAME",
            "INTERACTION_TYPE", "INTERACTION_TIMESTAMP", "INTERACTION_STATUS", "UPDATED_AT",
        ]

        start = client.start_group_export(
            group_id=group_id,
            dataset=dataset,
            columns=payload_columns,
            filters=filters,
            formats=[export_format],
        )
        export_id = start.get("data", {}).get("id")
        if not export_id:
            console.print("[red]Failed to start group export")
            continue

        t0 = time.time()
        while True:
            status = client.get_group_export_status(group_id, export_id)
            state = status.get("data", {}).get("attributes", {}).get("status", "unknown").lower()
            console.print(f"[dim]Status: {state}")
            if state in ("finished", "complete"):
                ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
                base_name = f"snyk_group_export_{dataset}_{export_id}_{ts}.{export_format}"
                files = client.download_group_export(group_id, status, base_name, export_format)
                if isinstance(files, list):
                    downloaded.extend(files)
                else:
                    downloaded.append(files)
                break
            if state in ("error", "failed", "cancelled"):
                console.print(f"[red]Group export ended with status: {state}")
                break
            if time.time() - t0 > timeout_sec:
                console.print("[red]Timeout waiting for group export")
                break
            time.sleep(poll_interval)

    if downloaded:
        console.print("\n[green]Downloaded files:")
        for f in downloaded:
            console.print(f"- {f}")
        # Attempt auto-combine if multiple CSVs
        if export_format == "csv":
            from snyk_export import SnykExportAPI as _C
            tmp = _C(token, base_url=base_url)
            folder = os.path.dirname(downloaded[0]) or "."
            ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            combined = os.path.join(folder, f"snyk_combined_export_{ts}.csv")
            csvs = [f for f in downloaded if f.lower().endswith(".csv")]
            if len(csvs) >= 2 and tmp.combine_csv_files(csvs, combined):
                console.print(f"[green]Combined CSV saved: {combined}")
                # Build schema and XML
                if Confirm.ask("Build XML + XSD from combined CSV?", default=True):
                    analysis = analyze_csv_structure(combined)
                    xsd = generate_xsd(analysis)
                    with open(os.path.join(folder, "snyk_export_schema.xsd"), "w", encoding="utf-8") as xf:
                        xf.write(xsd)
                    xml_name = f"snyk_export_{ts}.xml"
                    write_xml_from_csv(combined, os.path.join(folder, xml_name))
                    console.print(f"[green]XSD and XML saved in: {folder}")


def main():
    console.print("\n[bold blue]Snyk Group Export - Interactive Menu\n[/]")
    console.print("1) Run Group Export (issues/usage) and optionally build XML/XSD")
    console.print("2) Exit")
    sel = Prompt.ask("Choose", choices=["1", "2"], default="1")
    if sel == "1":
        run_group_export_flow()
    else:
        console.print("Goodbye!")
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())


