from dotenv import load_dotenv
import os

load_dotenv()
print(f"SNYK_API_TOKEN: {os.getenv('SNYK_API_TOKEN')}")
print(f"SNYK_GROUP_ID: {os.getenv('SNYK_GROUP_ID')}")
