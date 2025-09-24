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
                console.print("\n[bold]Available Groups:")
                groups = [
                    {"name": "Acme Company Organization", "id": "a8b06ecd-d0db-4a12-941d-c00691975a90"},
                    {"name": "Actions", "id": "788993e3-0241-4cc7-885d-4789d2a41ec5"},
                    {"name": "Azure DevOps Shop", "id": "48ad8276-fee9-456b-a935-d75cc0ba063f"},
                    {"name": "backend", "id": "c0aa30b3-2123-46f3-8171-1c2953485c32"},
                    {"name": "BitBucket", "id": "c655dde1-2a73-4f76-89b0-b7e7f0ae2dcd"},
                    {"name": "Bitbucket Demo", "id": "8c6a7f7d-a46b-4d6a-98ee-5b44ff992519"},
                    {"name": "Bitbucket Shop", "id": "8b9466b4-1f85-4fef-bf73-3b44184082fa"},
                    {"name": "CBIR Dev Team", "id": "e7f5d5d2-f25d-45be-b9f7-58cb0b74aad7"},
                    {"name": "CBIR Platform Team", "id": "26983627-fe27-4e94-bf8f-0050874cda60"},
                    {"name": "Certification Demo", "id": "492c82c0-8300-445d-9a64-7ce90cdc03db"},
                ]
                for i, group in enumerate(groups, 1):
                    console.print(f"{i}. {group['name']} (ID: {group['id']})")
                sel = input("\nEnter group number or ID: ").strip()
                if sel:
                    gid = None
                    gname = None
                    if sel.isdigit():
                        idx = int(sel)
                        if 1 <= idx <= len(groups):
                            gid = groups[idx-1]['id']
                            gname = groups[idx-1]['name']
                    if not gid:
                        for g in groups:
                            if g['id'] == sel:
                                gid = g['id']
                                gname = g['name']
                                break
                    if gid:
                        selected_group_id = gid
                        selected_group_name = gname
                        console.print(f"[green]Selected group: {selected_group_name} (ID: {selected_group_id})")
                        console.print(f"[dim]Group ID: {selected_group_id}")
                        console.print(f"[dim]Group Name: {selected_group_name}")
                    else:
                        console.print("[red]Invalid selection.")
            
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
