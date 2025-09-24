#!/usr/bin/env python3
"""
Script to analyze a Snyk export CSV file and generate an XSD schema.
"""
import os
import sys
import csv
import json
import argparse
from pathlib import Path
from datetime import datetime
import pandas as pd
from rich.console import Console
from rich.table import Table

# Initialize console
console = Console()

def analyze_csv_structure(csv_file):
    """Analyze the structure of the CSV file and return field information."""
    try:
        # Read the CSV file with pandas to handle various encodings and formats
        df = pd.read_csv(csv_file, nrows=1000)  # Read first 1000 rows for analysis
        
        # Get basic info
        total_rows = len(df)
        columns = df.columns.tolist()
        
        # Analyze each column
        columns_info = []
        for col in columns:
            # Get data type
            dtype = str(df[col].dtype)
            
            # Get sample values (non-null)
            sample_values = df[col].dropna().head(5).tolist()
            
            # Get basic statistics for numeric columns
            stats = {}
            if pd.api.types.is_numeric_dtype(df[col]):
                stats = df[col].describe().to_dict()
            
            # Get unique count and sample unique values for categorical data
            unique_count = df[col].nunique()
            sample_uniques = []
            if 1 < unique_count <= 10:  # Only include if not too many unique values
                sample_uniques = df[col].drop_duplicates().head(5).tolist()
            
            columns_info.append({
                'name': col,
                'dtype': dtype,
                'non_null_count': df[col].count(),
                'null_count': df[col].isnull().sum(),
                'unique_count': unique_count,
                'sample_values': sample_values,
                'sample_uniques': sample_uniques,
                'stats': stats
            })
        
        return {
            'file': str(csv_file),
            'total_rows': total_rows,
            'total_columns': len(columns),
            'columns': columns_info
        }
    except Exception as e:
        console.print(f"[red]Error analyzing CSV: {e}")
        return None

def generate_xsd(csv_analysis):
    """Generate an XSD schema from the CSV analysis."""
    if not csv_analysis:
        return None
    
    xsd_header = '''<?xml version="1.0" encoding="UTF-8"?>
<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema"
           elementFormDefault="qualified"
           targetNamespace="http://www.snyk.io/schema"
           xmlns:snyk="http://www.snyk.io/schema">

  <xs:element name="snyk_export">
    <xs:complexType>
      <xs:sequence>
        <xs:element name="issue" minOccurs="0" maxOccurs="unbounded">
          <xs:complexType>
            <xs:sequence>
'''

    # Add fields
    fields_xsd = ''
    for col in csv_analysis['columns']:
        # Map pandas dtypes to XSD types
        dtype_map = {
            'object': 'xs:string',
            'int64': 'xs:integer',
            'float64': 'xs:decimal',
            'bool': 'xs:boolean',
            'datetime64[ns]': 'xs:dateTime'
        }
        
        xsd_type = dtype_map.get(col['dtype'], 'xs:string')
        
        # Create field element
        field_name = col['name'].lower().replace(' ', '_').replace('.', '_')
        min_occurs = '0' if col['null_count'] > 0 else '1'
        
        # Add documentation with sample values
        doc = f"""              <xs:annotation>
                <xs:documentation>
                  Type: {col['dtype']}
                  Unique values: {col['unique_count']}
                  Sample values: {', '.join(map(str, col['sample_values'][:3]))}
                </xs:documentation>
              </xs:annotation>
"""
        field = f"""            {doc}            <xs:element name="{field_name}" type="{xsd_type}" minOccurs="{min_occurs}" maxOccurs="1"/>
"""
        fields_xsd += field
    
    xsd_footer = '''          </xs:sequence>
          </xs:complexType>
        </xs:element>
      </xs:sequence>
    </xs:complexType>
  </xs:element>
</xs:schema>
'''
    
    return xsd_header + fields_xsd + xsd_footer

def display_analysis(csv_analysis):
    """Display the CSV analysis in a nice format."""
    if not csv_analysis:
        return
    
    console.print(f"\n[bold]CSV Analysis Report[/]")
    console.print(f"File: {csv_analysis['file']}")
    console.print(f"Total Rows: {csv_analysis['total_rows']:,}")
    console.print(f"Total Columns: {csv_analysis['total_columns']}")
    
    # Create a table for column information
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Column", style="cyan")
    table.add_column("Type")
    table.add_column("Non-null")
    table.add_column("Unique")
    table.add_column("Sample Values")
    
    for col in csv_analysis['columns']:
        sample_values = ', '.join(str(x) for x in col['sample_values'][:3])
        if len(sample_values) > 40:
            sample_values = sample_values[:37] + '...'
            
        table.add_row(
            col['name'],
            col['dtype'],
            f"{col['non_null_count']:,}",
            f"{col['unique_count']:,}",
            sample_values
        )
    
    console.print("\n[bold]Column Information:[/]")
    console.print(table)

def main():
    parser = argparse.ArgumentParser(description='Analyze Snyk export CSV and generate XSD schema')
    parser.add_argument('csv_file', help='Path to the Snyk export CSV file')
    parser.add_argument('--xsd', help='Output XSD file path (optional)')
    
    args = parser.parse_args()
    
    # Check if file exists
    if not os.path.isfile(args.csv_file):
        console.print(f"[red]Error: File not found: {args.csv_file}")
        sys.exit(1)
    
    # Analyze the CSV file
    console.print(f"[bold]Analyzing {args.csv_file}...[/]")
    analysis = analyze_csv_structure(args.csv_file)
    
    if not analysis:
        console.print("[red]Failed to analyze the CSV file.")
        sys.exit(1)
    
    # Display the analysis
    display_analysis(analysis)
    
    # Generate and save XSD if requested
    if args.xsd:
        xsd_schema = generate_xsd(analysis)
        if xsd_schema:
            with open(args.xsd, 'w') as f:
                f.write(xsd_schema)
            console.print(f"\n[green]XSD schema saved to: {args.xsd}")
            
            # Also save a simplified JSON schema for reference
            json_schema = {
                'source': args.csv_file,
                'analysis_date': datetime.now().isoformat(),
                'columns': [
                    {
                        'name': col['name'],
                        'type': col['dtype'],
                        'description': f"Unique values: {col['unique_count']}",
                        'sample_values': col['sample_values'][:3]
                    }
                    for col in analysis['columns']
                ]
            }
            
            json_path = os.path.splitext(args.xsd)[0] + '.json'
            with open(json_path, 'w') as f:
                json.dump(json_schema, f, indent=2)
            console.print(f"[green]JSON schema saved to: {json_path}")

if __name__ == "__main__":
    main()
