#!/usr/bin/env python3
"""
Script to push STIX 2 data from local files to a TAXII server using cytaxii2.

This script uses the cytaxii2 library to:
1. Connect to the TAXII server
2. Perform discovery requests to understand the server's API
3. Find and validate collections
4. Upload STIX data to the appropriate collection
"""
import os
import json
import logging
import sys
from cytaxii2 import cytaxii2
import traceback
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# Configuration - Get values from environment variables
TAXII_DISCOVERY_URL = os.getenv('TAXII_DISCOVERY_URL')
TAXII_USERNAME = os.getenv('TAXII_USERNAME')
TAXII_PASSWORD = os.getenv('TAXII_PASSWORD')
TAXII_COLLECTION_ID = os.getenv('TAXII_COLLECTION_ID')
TAXII_VERSION = float(os.getenv('TAXII_VERSION', '2.1'))  # Convert to float for version
DATA_DIRECTORY = os.getenv('DATA_DIRECTORY')

# Validate required environment variables
required_vars = {
    'TAXII_DISCOVERY_URL': TAXII_DISCOVERY_URL,
    'TAXII_USERNAME': TAXII_USERNAME,
    'TAXII_PASSWORD': TAXII_PASSWORD,
    'TAXII_COLLECTION_ID': TAXII_COLLECTION_ID,
    'DATA_DIRECTORY': DATA_DIRECTORY
}

missing_vars = [var for var, value in required_vars.items() if not value]
if missing_vars:
    logger.error(f"Missing required environment variables: {', '.join(missing_vars)}")
    logger.error("Please ensure all required variables are set in your .env file")
    sys.exit(1)

def find_stix_files(data_dir):
    """Find all STIX JSON files in the given directory structure."""
    stix_files = []
    for root, _, files in os.walk(data_dir):
        for file in files:
            if file.endswith('_stix.json'):
                stix_files.append(os.path.join(root, file))
    return stix_files

def load_stix_data(file_path):
    """Load STIX data from a JSON file."""
    try:
        with open(file_path, 'r') as f:
            data = json.load(f)
        return data
    except Exception as e:
        logger.error(f"Error loading STIX data from {file_path}: {e}")
        return None

def perform_discovery(client):
    """
    Perform TAXII discovery requests to understand the server structure.
    Returns True if successful, False otherwise.
    """
    logger.info("Performing TAXII discovery request...")
    try:
        discovery_response = client.discovery_request()
        
        if discovery_response.get('status') != True:
            logger.error(f"TAXII discovery failed: {discovery_response}")
            return False
        
        # Log discovery information
        discovery_data = discovery_response.get('response', {})
        logger.info(f"TAXII Server Title: {discovery_data.get('title', 'Unknown')}")
        logger.info(f"TAXII Server Description: {discovery_data.get('description', 'No description')}")
        logger.info(f"TAXII Server Contact: {discovery_data.get('contact', 'No contact information')}")
        
        # Show API roots
        api_roots = discovery_data.get('api_roots', [])
        if api_roots:
            logger.info(f"Available API Roots: {', '.join(api_roots)}")
        else:
            logger.warning("No API roots found in discovery response")
        
        # Perform root discovery if available
        try:
            logger.info("Performing root discovery request...")
            root_response = client.root_discovery()
            
            if root_response.get('status') == True:
                root_data = root_response.get('response', {})
                logger.info(f"TAXII Version: {root_data.get('versions', ['Unknown'])}")
                logger.info(f"TAXII Max Content Length: {root_data.get('max_content_length', 'Unknown')}")
            else:
                logger.warning(f"Root discovery failed: {root_response}")
        except Exception as e:
            logger.warning(f"Root discovery not supported: {e}")
        
        return True
    except Exception as e:
        logger.error(f"Error during discovery: {e}")
        logger.debug(traceback.format_exc())
        return False

def discover_collections(client, target_collection_id=None):
    """
    Discover available collections and verify if the target collection is accessible.
    Returns (collection_found, collection_writable) tuple.
    """
    logger.info("Requesting collection information...")
    try:
        collections_response = client.collection_request()
        
        if collections_response.get('status') != True:
            logger.error(f"Failed to get collections: {collections_response}")
            return False, False
        
        collections = collections_response.get('response', {}).get('collections', [])
        logger.info(f"Server has {len(collections)} available collections")
        
        if not collections:
            logger.warning("No collections found or accessible")
            logger.debug(f"Response: {collections_response}")
            return False, False
        
        collection_found = False
        collection_writable = False
        
        # Print information about all collections
        for collection in collections:
            coll_id = collection.get('id', 'Unknown ID')
            title = collection.get('title', 'Untitled')
            can_read = collection.get('can_read', False)
            can_write = collection.get('can_write', False)
            
            logger.info(f"Collection: {title} (ID: {coll_id})")
            logger.info(f"  - Read access: {can_read}")
            logger.info(f"  - Write access: {can_write}")
            
            # Check if this is our target collection
            if target_collection_id and coll_id == target_collection_id:
                collection_found = True
                collection_writable = can_write
                logger.info(f"Found target collection: {title} (ID: {coll_id})")
                logger.info(f"Collection is {'writable' if can_write else 'read-only'}")
        
        return collection_found, collection_writable
    except Exception as e:
        logger.error(f"Error discovering collections: {e}")
        logger.debug(traceback.format_exc())
        return False, False

def push_stix_to_taxii(client, collection_id, stix_bundle):
    """
    Push STIX bundle to a TAXII collection.
    
    Args:
        client: cytaxii2 client object
        collection_id: ID of the collection to push to
        stix_bundle: STIX bundle as a dictionary
        
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        # Extract objects from the bundle
        if isinstance(stix_bundle, dict) and 'objects' in stix_bundle:
            # Get the bundle ID for logging
            bundle_id = stix_bundle.get('id', 'unknown')
            objects_count = len(stix_bundle['objects'])
            logger.info(f"Pushing bundle {bundle_id} with {objects_count} objects to collection {collection_id}")
            
            # Convert the bundle to a JSON string (cytaxii2 expects a string)
            stix_json = json.dumps(stix_bundle)
            
            # Send the bundle to the TAXII server
            response = client.inbox_request(collection_id=collection_id, stix_bundle=stix_json)
            
            # Check the response
            if response.get('status') == True:
                logger.info(f"Successfully pushed bundle to collection {collection_id}")
                return True
            else:
                logger.error(f"Error pushing bundle: {response}")
                return False
        else:
            logger.error("Invalid STIX bundle format")
            return False
    except Exception as e:
        logger.error(f"Error pushing STIX data: {e}")
        logger.debug(traceback.format_exc())
        return False

def main():
    """Main function to process STIX files and push to TAXII server."""
    logger.info("Starting TAXII push process")
    logger.info(f"TAXII Server: {TAXII_DISCOVERY_URL}")
    logger.info(f"TAXII Version: {TAXII_VERSION}")
    logger.info(f"Collection ID: {TAXII_COLLECTION_ID}")
    logger.info(f"Data Directory: {DATA_DIRECTORY}")
    
    # Find STIX files
    stix_files = find_stix_files(DATA_DIRECTORY)
    logger.info(f"Found {len(stix_files)} STIX files in {DATA_DIRECTORY}")
    
    if not stix_files:
        logger.error(f"No STIX files found in {DATA_DIRECTORY}")
        return 1
    
    try:
        # Create the cytaxii2 client
        logger.info(f"Connecting to TAXII server at {TAXII_DISCOVERY_URL}")
        
        # Try with different version formats if needed
        try:
            client = cytaxii2.cytaxii2(
                TAXII_DISCOVERY_URL, 
                TAXII_USERNAME, 
                TAXII_PASSWORD, 
                version=TAXII_VERSION  # Try with numeric value
            )
        except Exception as e:
            logger.warning(f"Error with numeric version format: {e}, trying string format")
            client = cytaxii2.cytaxii2(
                TAXII_DISCOVERY_URL, 
                TAXII_USERNAME, 
                TAXII_PASSWORD, 
                version=str(TAXII_VERSION)  # Try with string value "2.0"
            )
        
        # Perform discovery to understand the server
        if not perform_discovery(client):
            logger.error("Discovery process failed")
            return 1
        
        # Discover collections and verify our target collection
        collection_found, collection_writable = discover_collections(client, TAXII_COLLECTION_ID)
        
        if not collection_found:
            logger.error(f"Collection {TAXII_COLLECTION_ID} not found on the server")
            return 1
        
        if not collection_writable:
            logger.error(f"Collection {TAXII_COLLECTION_ID} is not writable")
            return 1
        
        # Push STIX data to the collection
        success_count = 0
        for file_path in stix_files:
            stix_bundle = load_stix_data(file_path)
            if stix_bundle:
                logger.info(f"Pushing data from {file_path}")
                if push_stix_to_taxii(client, TAXII_COLLECTION_ID, stix_bundle):
                    success_count += 1
        
        logger.info(f"Successfully pushed {success_count} out of {len(stix_files)} STIX files")
        return 0
        
    except Exception as e:
        logger.error(f"Error accessing TAXII server: {e}")
        logger.debug(traceback.format_exc())
        return 1

if __name__ == "__main__":
    sys.exit(main()) 