#!/usr/bin/env python3

import os
import sys
import json
import argparse
import sqlite3
from datetime import datetime

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

def create_test_dir() -> str:
    """Create a timestamped test directory"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    test_dir = os.path.join("data", f"id_test_{timestamp}")
    os.makedirs(test_dir, exist_ok=True)
    print(f"Created test directory: {test_dir}")
    return test_dir

def process_breach(api: TruKnoAPI, breach_id: str, output_path: str, db_file: str) -> str:
    """
    Process a breach ID and return the path to the generated STIX file
    """
    # Fetch breach data
    print(f"Fetching data for breach ID: {breach_id}")
    breach_data = api.get_breach_details(breach_id)
    
    if not breach_data:
        print(f"Error: No data returned for breach ID: {breach_id}")
        sys.exit(1)
    
    # Save raw data to a temporary file
    temp_input_path = os.path.join(output_path, f"{breach_id}_temp.json")
    with open(temp_input_path, 'w') as f:
        json.dump(breach_data, f, indent=2)
    
    # Convert to STIX
    stix_output_path = os.path.join(output_path, f"{breach_id}_stix.json")
    
    try:
        converter = TruKnoToSTIXConverter(
            temp_input_path, 
            stix_output_path,
            validate_patterns=True,
            db_file=db_file
        )
        converter.convert()
        print(f"Created STIX file: {stix_output_path}")
    except Exception as e:
        print(f"Error converting data to STIX format: {str(e)}")
        sys.exit(1)
    finally:
        # Clean up temp file
        if os.path.exists(temp_input_path):
            os.remove(temp_input_path)
    
    return stix_output_path

def extract_ids_from_stix(stix_file: str) -> dict:
    """
    Extract STIX IDs from a STIX bundle file
    Returns a dictionary with object type as key and a list of IDs as value
    """
    with open(stix_file, 'r') as f:
        stix_bundle = json.load(f)
    
    ids_by_type = {}
    
    # Skip the bundle object itself
    for obj in stix_bundle.get('objects', []):
        obj_type = obj.get('type')
        obj_id = obj.get('id')
        
        if obj_type and obj_id:
            if obj_type not in ids_by_type:
                ids_by_type[obj_type] = []
            ids_by_type[obj_type].append(obj_id)
    
    return ids_by_type

def compare_id_sets(ids1: dict, ids2: dict) -> bool:
    """
    Compare two sets of IDs and return True if they match
    Print information about any differences found
    """
    all_types = set(ids1.keys()) | set(ids2.keys())
    all_match = True
    
    print("\nComparing STIX IDs between runs:")
    print("=" * 50)
    
    for obj_type in all_types:
        set1 = set(ids1.get(obj_type, []))
        set2 = set(ids2.get(obj_type, []))
        
        if set1 == set2:
            print(f"✅ {obj_type}: All {len(set1)} IDs match")
        else:
            all_match = False
            only_in_1 = set1 - set2
            only_in_2 = set2 - set1
            common = set1 & set2
            
            print(f"❌ {obj_type}: Mismatch found")
            print(f"   - Common IDs: {len(common)}")
            print(f"   - Only in first run: {len(only_in_1)}")
            print(f"   - Only in second run: {len(only_in_2)}")
            
            if only_in_1:
                print(f"   - Examples only in first run: {list(only_in_1)[:2]}")
            if only_in_2:
                print(f"   - Examples only in second run: {list(only_in_2)[:2]}")
    
    return all_match

def print_db_stats(db_file: str) -> None:
    """Print statistics about the database contents"""
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    
    print("\nDatabase Statistics:")
    print("=" * 50)
    
    # Get table names
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = cursor.fetchall()
    
    for table in tables:
        table_name = table[0]
        cursor.execute(f"SELECT COUNT(*) FROM {table_name}")
        count = cursor.fetchone()[0]
        print(f"{table_name}: {count} entries")
    
    # Sample entries from each table
    for table in tables:
        table_name = table[0]
        cursor.execute(f"SELECT * FROM {table_name} LIMIT 3")
        rows = cursor.fetchall()
        if rows:
            print(f"\nSample entries from {table_name}:")
            for row in rows:
                print(f"  - {row}")
    
    conn.close()

def main():
    parser = argparse.ArgumentParser(
        description='Test SQLite ID mapping consistency by processing the same breach ID twice'
    )
    parser.add_argument('breach_id', help='TruKno breach ID to test')
    parser.add_argument('--api-key', help='TruKno API key (defaults to TRUKNO_API_KEY environment variable)')
    parser.add_argument('--db-file', default='trukno_stix_mapping.db', help='Path to SQLite database file')
    
    args = parser.parse_args()
    
    # Set API key if provided
    if args.api_key:
        os.environ["TRUKNO_API_KEY"] = args.api_key
    
    # Create test directory
    test_dir = create_test_dir()
    
    # Initialize the API client
    try:
        api = TruKnoAPI()
    except ValueError as e:
        print(f"Error initializing TruKno API: {str(e)}")
        print("Please ensure TRUKNO_API_KEY is set in your environment or provide it with --api-key")
        sys.exit(1)
    
    # Process the breach twice
    print("\n==== First Run ====")
    first_run_dir = os.path.join(test_dir, "run1")
    os.makedirs(first_run_dir, exist_ok=True)
    first_stix_file = process_breach(api, args.breach_id, first_run_dir, args.db_file)
    
    print("\n==== Second Run ====")
    second_run_dir = os.path.join(test_dir, "run2")
    os.makedirs(second_run_dir, exist_ok=True)
    second_stix_file = process_breach(api, args.breach_id, second_run_dir, args.db_file)
    
    # Extract and compare IDs
    first_run_ids = extract_ids_from_stix(first_stix_file)
    second_run_ids = extract_ids_from_stix(second_stix_file)
    
    # Compare the ID sets
    ids_match = compare_id_sets(first_run_ids, second_run_ids)
    
    # Print database statistics
    print_db_stats(args.db_file)
    
    # Final result
    print("\nTest Result:")
    print("=" * 50)
    if ids_match:
        print("✅ PASSED: All STIX IDs are consistent between runs")
        print(f"The SQLite database mapping is working correctly!")
    else:
        print("❌ FAILED: Some STIX IDs differ between runs")
        print(f"Please check the implementation of the SQLite mapping")
    
    print(f"\nTest files saved in: {test_dir}")

if __name__ == "__main__":
    main() 