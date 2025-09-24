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
            console.print("2. Exit")
            
            # Get user choice
            try:
                choice = input("\nEnter your choice (1-2): ").strip()
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
