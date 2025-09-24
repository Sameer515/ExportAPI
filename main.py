import os
import sys
from typing import Optional
from dotenv import load_dotenv
from rich.console import Console
from rich.prompt import Confirm
from datetime import datetime
from snyk_export import SnykExportAPI

console = Console()

def main():
    """
    Main entry point for the Snyk Export Tool.
    """
    try:
        # Load environment variables
        load_dotenv()
        
        # Get API token from environment variables
        api_token = os.getenv("SNYK_API_TOKEN")
        if not api_token:
            console.print("[red]Error: SNYK_API_TOKEN environment variable not set")
            console.print("Please create a .env file with your Snyk API token:")
            console.print("SNYK_API_TOKEN=your_api_token_here")
            return 1
            
        # Initialize the Snyk API client
        snyk = SnykExportAPI(api_token)
        
        # Main menu loop
        export_files = []  # Track exported files
        selected_group_id: Optional[str] = None
        selected_group_name: str = ""
        
        while True:
            # Display menu
            console.print("\n" + "="*50)
            console.print("[bold blue]Snyk Export API Tool")
            console.print("="*50)
            console.print("1. Select Group")
            console.print("2. List Organizations in Selected Group")
            console.print("3. Export for Single Organization")
            console.print("4. Export for All Organizations in Selected Group")
            console.print("5. Retrieve Project Last Tested Date")
            console.print("6. Advanced Export Settings")
            console.print("7. View Available Filters and Columns")
            console.print("8. Exit")
            
            # Get user choice
            try:
                choice = input("\nEnter your choice (1-8): ").strip()
            except (EOFError, KeyboardInterrupt):
                console.print("\n[yellow]Operation cancelled by user.")
                return 0
            
            if choice == "1":
                # Select group
                try:
                    console.print("\n[dim]Fetching groups...")
                    groups = snyk.list_groups()
                    if not groups:
                        console.print("[yellow]No groups found or you don't have permission to view groups.")
                    else:
                        console.print("\n[bold]Available Groups:")
                        for i, group in enumerate(groups, 1):
                            group_name = group.get('name', 'Unnamed Group')
                            gid = group.get('id', 'N/A')
                            console.print(f"{i}. {group_name} (ID: {gid})")
                        sel = input("\nEnter group number or ID: ").strip()
                        if sel:
                            gid = None
                            gname = None
                            if sel.isdigit():
                                idx = int(sel)
                                if 1 <= idx <= len(groups):
                                    gid = groups[idx-1].get('id')
                                    gname = groups[idx-1].get('name', '')
                            if not gid:
                                for g in groups:
                                    if g.get('id') == sel:
                                        gid = g.get('id')
                                        gname = g.get('name', '')
                                        break
                            # Fallback: accept arbitrary ID even if not present in the list
                            if not gid and sel:
                                gid = sel
                                gname = sel
                            if gid:
                                selected_group_id = gid
                                selected_group_name = gname or gid
                                console.print(f"[green]Selected group: {selected_group_name} ({selected_group_id})")
                            else:
                                console.print("[red]Invalid selection.")
                except Exception as e:
                    console.print(f"[red]Error selecting group: {str(e)}")
                    if hasattr(e, 'response') and hasattr(e.response, 'text'):
                        console.print(f"[dim]Response: {e.response.text}")
            
            elif choice == "2":
                # List organizations in the selected group
                try:
                    if not selected_group_id:
                        console.print("[yellow]Please select a group first (option 1).")
                        continue
                    console.print(f"\n[dim]Fetching organizations for group {selected_group_id}...")
                    orgs = snyk.list_organizations(selected_group_id)
                    
                    if orgs:
                        console.print(f"\n[bold]Organizations in Group {selected_group_name or selected_group_id}:")
                        for i, org in enumerate(orgs, 1):
                            org_name = org.get('name', 'Unnamed Organization')
                            org_id = org.get('id', 'N/A')
                            console.print(f"{i}. {org_name} (ID: {org_id})")
                    else:
                        console.print(f"[yellow]No organizations found in selected group or you don't have access.")
                        console.print(f"[dim]You can still export by using the selected group ID as an organization ID in option 3.")
                        
                except (EOFError, KeyboardInterrupt):
                    console.print("\n[yellow]Operation cancelled by user.")
                except Exception as e:
                    console.print(f"[red]Error listing organizations: {str(e)}")
                    if hasattr(e, 'response') and hasattr(e.response, 'text'):
                        console.print(f"[dim]Response: {e.response.text}")
            
            elif choice == "3":
                # Start export for a single organization
                try:
                    org_id = ""
                    org_name = "unknown"
                    if selected_group_id:
                        orgs = snyk.list_organizations(selected_group_id)
                        if orgs:
                            console.print("\n[bold]Select Organization:")
                            for i, org in enumerate(orgs, 1):
                                console.print(f"{i}. {org.get('name','Unnamed')} (ID: {org.get('id','N/A')})")
                            sel = input("Enter number or ID: ").strip()
                            if sel.isdigit():
                                idx = int(sel)
                                if 1 <= idx <= len(orgs):
                                    org_id = orgs[idx-1].get('id')
                                    org_name = orgs[idx-1].get('name','unknown')
                            if not org_id:
                                for o in orgs:
                                    if o.get('id') == sel:
                                        org_id = o.get('id')
                                        org_name = o.get('name','unknown')
                                        break
                        else:
                            # Fallback to using the selected group ID as the org ID
                            if Confirm.ask(f"No organizations listed. Use selected group as org ID ({selected_group_id})?"):
                                org_id = selected_group_id
                                org_name = selected_group_name or "unknown"
                    if not org_id:
                        org_id = input("Enter Organization ID: ").strip()
                        org_name = input("Enter Organization Name (optional, for display): ").strip() or "unknown"
                    
                    if org_id:
                        console.print(f"\n[bold]Starting export for organization: {org_name} (ID: {org_id})[/]")
                        downloaded_files = snyk.start_export_workflow(org_id, org_name)
                        
                        if downloaded_files:
                            console.print("\n[green]✓ Export completed for the following files:[/]")
                            for file in downloaded_files:
                                console.print(f"- {file}")
                            
                            # Offer to combine
                            if len(downloaded_files) > 1 and Confirm.ask("\nDo you want to combine these files?"):
                                # Ask format
                                combine_format = input("Combine as CSV or JSON? (csv/json) [csv]: ").strip().lower() or "csv"
                                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                                if combine_format == 'json':
                                    json_files = [f for f in downloaded_files if f.lower().endswith('.json')]
                                    if len(json_files) >= 2:
                                        combined_file = f"snyk_combined_export_{timestamp}.json"
                                        if snyk.combine_json_files(json_files, combined_file):
                                            console.print(f"[green]✓ Combined export saved to: {combined_file}[/]")
                                    else:
                                        console.print("[yellow]Not enough JSON files to combine.")
                                else:
                                    csv_files = [f for f in downloaded_files if f.lower().endswith('.csv')]
                                    if len(csv_files) >= 2:
                                        combined_file = f"snyk_combined_export_{timestamp}.csv"
                                        if snyk.combine_csv_files(csv_files, combined_file):
                                            console.print(f"[green]✓ Combined export saved to: {combined_file}[/]")
                                    else:
                                        console.print("[yellow]Not enough CSV files to combine.")
                
                except (EOFError, KeyboardInterrupt):
                    console.print("\n[yellow]Operation cancelled by user.")
                except Exception as e:
                    console.print(f"[red]Error during export: {e}")
            
            elif choice == "4":
                # Start export for entire group using group-level export API
                try:
                    if not selected_group_id:
                        console.print("[yellow]Please select a group first (option 1).")
                        continue

                    orgs = snyk.list_organizations(selected_group_id)
                    org_count = len(orgs)
                    if org_count:
                        console.print(
                            f"\n[bold]Found {org_count} organizations in group {selected_group_name or selected_group_id}[/]"
                        )
                    else:
                        console.print(
                            f"[yellow]No organizations returned for group {selected_group_name or selected_group_id}."
                        )

                    if not Confirm.ask("Do you want to run a group-level export for this group?"):
                        continue

                    downloaded_files = snyk.start_group_export_workflow(
                        group_id=selected_group_id,
                        group_name=selected_group_name or selected_group_id,
                    )

                    export_files.extend(downloaded_files)

                    if downloaded_files:
                        console.print("\n[green]✓ Group export completed![/]")
                        if Confirm.ask("\nDo you want to combine all results?"):
                            combine_format = input("Combine as CSV or JSON? (csv/json) [csv]: ").strip().lower() or "csv"
                            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                            if combine_format == 'json':
                                json_files = [f for f in downloaded_files if f.lower().endswith('.json')]
                                if len(json_files) >= 2:
                                    combined_file = f"snyk_combined_export_{timestamp}.json"
                                    if snyk.combine_json_files(json_files, combined_file):
                                        console.print(f"[green]✓ Combined JSON export saved to: {combined_file}[/]")
                                else:
                                    console.print("[yellow]Not enough JSON files to combine.")
                            else:
                                csv_files = [f for f in downloaded_files if f.lower().endswith('.csv')]
                                if len(csv_files) >= 2:
                                    combined_file = f"snyk_combined_export_{timestamp}.csv"
                                    if snyk.combine_csv_files(csv_files, combined_file):
                                        console.print(f"[green]✓ Combined CSV export saved to: {combined_file}[/]")
                                else:
                                    console.print("[yellow]Not enough CSV files to combine.")
                    else:
                        console.print("[yellow]No files were downloaded from the group export.")

                except (EOFError, KeyboardInterrupt):
                    console.print("\n[yellow]Operation cancelled by user.")
                except Exception as e:
                    console.print(f"[red]Error during group export: {e}")
                    import traceback
                    traceback.print_exc()
            
            elif choice == "5":
                # Retrieve Project Last Tested Date
                try:
                    org_id = input("Enter Organization ID: ").strip()
                    project_id = input("Enter Project ID: ").strip()
                    if org_id and project_id:
                        snyk.get_project_last_tested_date(org_id, project_id)
                    else:
                        console.print("[red]Both Organization ID and Project ID are required.")
                except (EOFError, KeyboardInterrupt):
                    console.print("\n[yellow]Operation cancelled by user.")
                except Exception as e:
                    console.print(f"[red]Error: {e}")
            
            elif choice == "6":
                # Advanced Export Settings
                console.print("\n[bold]Advanced Export Settings:")
                console.print("1. Set Custom Date Range")
                console.print("2. Select Specific Datasets")
                console.print("3. Configure Enrichment Options")
                console.print("4. Back to Main Menu")
                sub_choice = input("\nEnter your choice (1-4): ").strip()
                if sub_choice == "1":
                    console.print("[dim]Custom date range settings can be configured in the export workflow.[/]")
                elif sub_choice == "2":
                    console.print("[dim]Dataset selection is available in the export options.[/]")
                elif sub_choice == "3":
                    console.print("[dim]Enrichment is automatically applied to all exports.[/]")
                elif sub_choice == "4":
                    continue
                else:
                    console.print("[red]Invalid choice.")
            
            elif choice == "7":
                # Display available filters and columns
                console.print("\n[bold]Available Filters:")
                console.print("-" * 30)
                console.print("- Environment (e.g., BACKEND, EXTERNAL)")
                console.print("- Lifecycle (e.g., PRODUCTION, DEVELOPMENT)")
                console.print("- Severity (e.g., critical, high, medium, low)")
                console.print("- Issue Type (e.g., vuln, license, configuration)")
                console.print("- Issue Status (e.g., open, resolved, ignored)")
                console.print("- Date Range (introduced/updated)")
                console.print("- Project filters (id/name/source)")
                console.print("\n[bold]Available Columns (dataset dependent):")
                console.print("(Refer to Snyk docs for the full list by dataset)")
            
            elif choice == "8":
                console.print("[bold]Goodbye!")
                return 0
                
            else:
                console.print("[red]Invalid choice. Please enter a number between 1 and 8.")

    except Exception as e:
        console.print(f"\n[red]A fatal error occurred: {e}")
        console.print("Please check your configuration and try again.")
        return 1

if __name__ == "__main__":
    main()
