#!/usr/bin/env python3

import os
import sys
import argparse
import json
from datetime import datetime
import shutil
from typing import List

# Import the TruKno API class
try:
    from trukno_api import TruKnoAPI
except ImportError:
    print("Error: trukno_api.py not found. Make sure it's in the same directory.")
    sys.exit(1)

# Import the STIX converter
try:
    from trukno_stix_converter import TruKnoToSTIXConverter
except ImportError:
    print("Error: trukno_stix_converter.py not found. Make sure it's in the same directory.")
    sys.exit(1)

def create_output_dir() -> str:
    """Create a timestamped output directory for this run"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = os.path.join("data", f"trukno_run_{timestamp}")
    
    # Create the directory
    os.makedirs(output_dir, exist_ok=True)
    print(f"Created output directory: {output_dir}")
    return output_dir

def process_breach_id(api: TruKnoAPI, breach_id: str, output_dir: str, db_file: str) -> None:
    """
    Process a single breach ID:
    1. Fetch the data from TruKno API
    2. Save the raw JSON response
    3. Convert to STIX format
    4. Save the STIX data
    """
    print(f"\nProcessing breach ID: {breach_id}")
    
    # Create a subdirectory for this breach ID
    breach_dir = os.path.join(output_dir, breach_id)
    os.makedirs(breach_dir, exist_ok=True)
    
    # Fetch breach data using TruKno API
    print(f"Fetching data for breach ID: {breach_id}")
    breach_data = api.get_breach_details(breach_id)
    
    if not breach_data:
        print(f"Error: No data returned for breach ID: {breach_id}")
        return
    
    # Save the raw JSON response
    raw_json_path = os.path.join(breach_dir, f"{breach_id}_raw.json")
    with open(raw_json_path, 'w') as f:
        json.dump(breach_data, f, indent=2)
    print(f"Saved raw JSON data to: {raw_json_path}")
    
    # Convert to STIX
    print(f"Converting data to STIX format")
    stix_output_path = os.path.join(breach_dir, f"{breach_id}_stix.json")
    
    # Create a temporary file for the converter to read from
    temp_input_path = os.path.join(breach_dir, f"{breach_id}_temp.json")
    
    try:
        # Write the data to the temporary file
        with open(temp_input_path, 'w') as f:
            json.dump(breach_data, f, indent=2)
        
        # Convert the data
        try:
            converter = TruKnoToSTIXConverter(
                temp_input_path, 
                stix_output_path,
                validate_patterns=True,
                db_file=db_file
            )
            converter.convert()
            print(f"Completed processing for breach ID: {breach_id}")
        except Exception as e:
            print(f"Error converting data to STIX format: {str(e)}")
            print(f"Raw data is still available at: {raw_json_path}")
    finally:
        # Clean up the temporary file
        if os.path.exists(temp_input_path):
            try:
                os.remove(temp_input_path)
            except Exception as e:
                print(f"Warning: Failed to remove temporary file {temp_input_path}: {str(e)}")

def main():
    parser = argparse.ArgumentParser(
        description='Process multiple TruKno breach IDs, fetch data, and convert to STIX format'
    )
    parser.add_argument('breach_ids', nargs='+', help='One or more TruKno breach IDs to process')
    parser.add_argument('--api-key', help='TruKno API key (defaults to TRUKNO_API_KEY environment variable)')
    parser.add_argument('--db-file', default='trukno_stix_mapping.db', help='Path to SQLite database file for ID mapping')
    
    args = parser.parse_args()
    
    # Set API key in environment variable if provided
    if args.api_key:
        os.environ["TRUKNO_API_KEY"] = args.api_key
    
    # Create the output directory for this run
    output_dir = create_output_dir()
    
    # Initialize the TruKno API
    try:
        api = TruKnoAPI()
    except ValueError as e:
        print(f"Error initializing TruKno API: {str(e)}")
        print("Please ensure TRUKNO_API_KEY is set in your environment or provide it with --api-key")
        sys.exit(1)
    
    # Process each breach ID
    for breach_id in args.breach_ids:
        try:
            process_breach_id(api, breach_id, output_dir, args.db_file)
        except Exception as e:
            print(f"Error processing breach ID {breach_id}: {str(e)}")
    
    print(f"\nProcessing complete. All files saved in: {output_dir}")
    
    # Summary
    print(f"\nSummary:")
    print(f"Processed {len(args.breach_ids)} breach IDs")
    print(f"Output directory: {output_dir}")
    print(f"Using database file: {args.db_file}")

if __name__ == "__main__":
    main() 