#!/usr/bin/env python3
import os
import sys
import argparse
import pandas as pd
import requests
from datetime import datetime
from typing import Optional

# Reuse analysis/xsd generation
from csv_to_xsd import analyze_csv_structure, generate_xsd


def find_combined_csv(folder: str) -> Optional[str]:
    """Pick the combined CSV in folder; if not present, fallback to any CSV."""
    if not os.path.isdir(folder):
        return None
    # Prefer a combined file naming
    for name in os.listdir(folder):
        if name.lower().startswith("snyk_combined_export_") and name.lower().endswith(".csv"):
            return os.path.join(folder, name)
    # Fallback: first CSV in folder
    for name in os.listdir(folder):
        if name.lower().endswith(".csv"):
            return os.path.join(folder, name)
    return None


def write_xml_from_csv(csv_path: str, xml_path: str, root_tag: str = "snyk_export", row_tag: str = "issue") -> None:
    df = pd.read_csv(csv_path)

    # Open and stream-write XML to avoid big memory spikes
    with open(xml_path, "w", encoding="utf-8") as f:
        f.write("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n")
        f.write(f"<{root_tag}>\n")

        # Emit each row
        for _, row in df.iterrows():
            f.write(f"  <{row_tag}>\n")
            for col in df.columns:
                tag = str(col).strip().lower().replace(" ", "_").replace(".", "_")
                val = "" if pd.isna(row[col]) else str(row[col])
                # Basic XML escaping
                val = (val
                       .replace("&", "&amp;")
                       .replace("<", "&lt;")
                       .replace(">", "&gt;")
                       .replace('"', "&quot;")
                       .replace("'", "&apos;"))
                f.write(f"    <{tag}>{val}</{tag}>\n")
            # Add v1 project payload if IDs present
            org_id = None
            project_id = None
            for c in df.columns:
                cl = str(c).strip().upper()
                if cl in ("ORG_PUBLIC_ID", "ORG_ID"):
                    if not pd.isna(row[c]):
                        org_id = str(row[c])
                if cl in ("PROJECT_PUBLIC_ID", "PROJECT_ID"):
                    if not pd.isna(row[c]):
                        project_id = str(row[c])
            if org_id and project_id and os.getenv("SNYK_API_TOKEN"):
                try:
                    url = f"https://api.snyk.io/v1/org/{org_id}/project/{project_id}"
                    headers = {"Authorization": f"token {os.getenv('SNYK_API_TOKEN')}", "Content-Type": "application/json"}
                    resp = requests.get(url, headers=headers, timeout=15)
                    if resp.status_code == 200:
                        proj = resp.json()
                        f.write("    <project_v1>\n")
                        for k, v in proj.items():
                            ktag = str(k).strip().lower().replace(" ", "_").replace(".", "_")
                            sval = "" if v is None else str(v)
                            sval = (sval
                                    .replace("&", "&amp;")
                                    .replace("<", "&lt;")
                                    .replace(">", "&gt;")
                                    .replace('"', "&quot;")
                                    .replace("'", "&apos;"))
                            f.write(f"      <{ktag}>{sval}</{ktag}>\n")
                        f.write("    </project_v1>\n")
                except Exception:
                    pass
            f.write(f"  </{row_tag}>\n")

        f.write(f"</{root_tag}>\n")


def main():
    parser = argparse.ArgumentParser(description="Build XSD schema and XML database from a combined CSV folder")
    parser.add_argument("--folder", required=True, help="Path to the exports dated folder (e.g., exports/20250923_224329)")
    parser.add_argument("--xml-name", default=None, help="Output XML filename (default: derived from folder)")
    parser.add_argument("--xsd-name", default=None, help="Output XSD filename (default: snyk_export_schema.xsd)")
    args = parser.parse_args()

    folder = args.folder
    csv_path = find_combined_csv(folder)
    if not csv_path:
        print(f"No CSV found in folder: {folder}")
        return 1

    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    xml_name = args.xml_name or f"snyk_export_{ts}.xml"
    xsd_name = args.xsd_name or "snyk_export_schema.xsd"

    xml_path = os.path.join(folder, xml_name)
    xsd_path = os.path.join(folder, xsd_name)

    # Build XSD from CSV analysis
    analysis = analyze_csv_structure(csv_path)
    if not analysis:
        print("Failed to analyze CSV for XSD generation.")
        return 1
    xsd = generate_xsd(analysis)
    if not xsd:
        print("Failed to generate XSD.")
        return 1
    with open(xsd_path, "w", encoding="utf-8") as f:
        f.write(xsd)
    print(f"XSD saved: {xsd_path}")

    # Build XML database file
    write_xml_from_csv(csv_path, xml_path)
    print(f"XML saved: {xml_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())


