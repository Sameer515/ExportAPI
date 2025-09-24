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
            if selected_group_id:
                console.print(f"[dim]Selected Group: {selected_group_name} (ID: {selected_group_id})[/]")
                console.print("1. List Organizations in Selected Group")
                console.print("2. Export for Single Organization")
                console.print("3. Export for All Organizations in Selected Group")
                console.print("4. Change Group")
                console.print("5. Exit")
                choice = input("\nEnter your choice (1-5): ").strip()
                if choice == "1":
                    # List organizations in the selected group
                    try:
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
                            console.print(f"[dim]You can still export by using the selected group ID as an organization ID in option 2.")
                    except Exception as e:
                        console.print(f"[red]Error listing organizations: {str(e)}")
                elif choice == "2":
                    # Export for single organization
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
                    except Exception as e:
                        console.print(f"[red]Error during export: {e}")
                elif choice == "3":
                    # Export for all organizations in selected group
                    try:
                        if not selected_group_id:
                            console.print("[yellow]Please select a group first.")
                            continue
                        orgs = snyk.list_organizations(selected_group_id)
                        org_count = len(orgs)
                        if org_count:
                            console.print(f"\n[bold]Found {org_count} organizations in group {selected_group_name or selected_group_id}[/]")
                        else:
                            console.print(f"[yellow]No organizations returned for group {selected_group_name or selected_group_id}.")
                        if not Confirm.ask("Do you want to run a group-level export for this group?"):
                            continue
                        downloaded_files = snyk.start_group_export_workflow(
                            group_id=selected_group_id,
                            group_name=selected_group_name or selected_group_id,
                        )
                        export_files.extend(downloaded_files)
                        if downloaded_files:
                            console.print("\n[green]✓ Group export completed![/]")
                        else:
                            console.print("[yellow]No files were downloaded from the group export.")
                    except Exception as e:
                        console.print(f"[red]Error during group export: {e}")
                        import traceback
                        traceback.print_exc()
                elif choice == "4":
                    # Change group
                    selected_group_id = None
                    selected_group_name = ""
                    console.print("[green]Group unselected. Returning to main menu.")
                elif choice == "5":
                    console.print("[bold]Goodbye!")
                    return 0
                else:
                    console.print("[red]Invalid choice. Please enter a number between 1 and 5.")
            else:
                console.print("1. Select Group")
                console.print("2. Exit")
                choice = input("\nEnter your choice (1-2): ").strip()
                if choice == "1":
                    # Select group
                    try:
                        console.print("\n[dim]Fetching groups...")
                        groups = snyk.list_groups()
                        if not groups:
                            console.print("[yellow]No groups found or you don't have permission to view groups.")
                            console.print("[dim]You can still enter a group ID manually.")
                            manual_group_id = input("Enter group ID: ").strip()
                            if manual_group_id:
                                selected_group_id = manual_group_id
                                selected_group_name = manual_group_id
                                console.print(f"[green]Selected group: {selected_group_name} (ID: {selected_group_id})")
                                console.print(f"[dim]Group ID: {selected_group_id}")
                                console.print(f"[dim]Group Name: {selected_group_name}")
                            else:
                                console.print("[red]No group ID entered. Returning to menu.")
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
                                    console.print(f"[green]Selected group: {selected_group_name} (ID: {selected_group_id})")
                                    console.print(f"[dim]Group ID: {selected_group_id}")
                                    console.print(f"[dim]Group Name: {selected_group_name}")
                                else:
                                    console.print("[red]Invalid selection.")
                    except Exception as e:
                        console.print(f"[red]Error selecting group: {str(e)}")
                        if hasattr(e, 'response') and hasattr(e.response, 'text'):
                            console.print(f"[dim]Response: {e.response.text}")
                elif choice == "2":
                    console.print("[bold]Goodbye!")
                    return 0
                else:
                    console.print("[red]Invalid choice. Please enter a number between 1 and 2.")

    except Exception as e:
        console.print(f"\n[red]A fatal error occurred: {e}")
        console.print("Please check your configuration and try again.")
        return 1

if __name__ == "__main__":
    main()
