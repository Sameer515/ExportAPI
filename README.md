# Snyk Export API Tool

A command-line tool to interact with the Snyk Export API, allowing you to export issues and dependencies data from your Snyk account.

## Features

- Start new export jobs for issues or dependencies
- Check the status of export jobs
- Download completed export files
- Interactive menu-based interface
- Rich console output with formatting

## Prerequisites

- Python 3.7+
- Snyk API token with appropriate permissions
- Snyk Group ID

## Installation

1. Clone this repository or download the files
2. Install the required dependencies:

```bash
pip install -r requirements.txt
```

3. Copy the example environment file and update it with your credentials:

```bash
cp .env.example .env
```

4. Edit the `.env` file and add your Snyk API token and Group ID:

```
SNYK_API_TOKEN=your_snyk_api_token_here
SNYK_GROUP_ID=your_snyk_group_id_here
```

## Usage

Run the tool with:

```bash
python snyk_export.py
```

The tool provides an interactive menu with the following options:

1. **Start New Export**: Start a new export job for issues or dependencies
2. **Check Export Status**: Check the status of an existing export job
3. **Download Export**: Download a completed export file
4. **Exit**: Exit the application

## Getting Help

For more information about the Snyk Export API, please refer to the [official documentation](https://docs.snyk.io/snyk-api/reference/export).

## License

This project is open source and available under the [MIT License](LICENSE).
