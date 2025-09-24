#!/usr/bin/env python3
"""
Test script to generate a sample Snyk export and analyze its structure.
"""
import os
import sys
from snyk_export import SnykExportAPI
from datetime import datetime, timedelta

def main():
    # Initialize the Snyk API client
    api_token = os.getenv('SNYK_API_TOKEN')
    if not api_token:
        print("Error: SNYK_API_TOKEN environment variable not set")
        sys.exit(1)
    
    snyk = SnykExportAPI(api_token)
    
    # List organizations
    print("Fetching organizations...")
    orgs = snyk.list_organizations()
    if not orgs:
        print("No organizations found or access denied.")
        sys.exit(1)
    
    # Use the first organization
    org = orgs[0]
    org_id = org['id']
    org_name = org.get('name', 'unknown')
    print(f"Using organization: {org_name} (ID: {org_id})")
    
    # Set the organization ID
    snyk.org_id = org_id
    
    # Define date range for the export (last 30 days)
    to_date = datetime.utcnow()
    from_date = to_date - timedelta(days=30)
    
    # Format dates as ISO 8601 strings
    date_format = "%Y-%m-%dT%H:%M:%SZ"
    from_date_str = from_date.strftime(date_format)
    to_date_str = to_date.strftime(date_format)
    
    # Start export with all parameters
    print("Starting export with the following parameters:")
    print(f"- Date range: {from_date_str} to {to_date_str}")
    print("- Environment: PRODUCTION")
    print("- Lifecycle: PRODUCTION")
    print("- Formats: CSV")
    
    try:
        export_result = snyk.start_export(
            export_type="issues",
            org_id=org_id,
            dataset="issues",
            environment=["PRODUCTION"],
            introduced_from=from_date_str,
            introduced_to=to_date_str,
            lifecycle=["PRODUCTION"],
            updated_from=from_date_str,
            updated_to=to_date_str,
            formats=["csv"]
        )
        
        if not export_result or 'data' not in export_result:
            print("Failed to start export:", export_result)
            sys.exit(1)
        
        # Save the export
        output_file = f"snyk_export_{org_id}_sample.csv"
        print(f"\nSaving export to {output_file}...")
        success = snyk.download_export(export_result, output_file, format='csv')
        
        if success:
            print(f"\n✅ Success! Sample export saved to: {output_file}")
            print("\nTo analyze the export structure, run:")
            print(f"python csv_to_xsd.py {output_file} --xsd snyk_export_schema.xsd")
        else:
            print("❌ Failed to save export.")
            
    except Exception as e:
        print(f"\n❌ An error occurred: {e}")
        if hasattr(e, 'response') and hasattr(e.response, 'text'):
            print("Response:", e.response.text)
        sys.exit(1)

if __name__ == "__main__":
    main()
