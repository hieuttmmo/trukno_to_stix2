import requests
import os
import json
from typing import Dict, Optional, List, Union
from dotenv import load_dotenv
from datetime import datetime

class TruKnoAPI:
    def __init__(self):
        load_dotenv()
        self.base_url = "https://api.trukno.com/V1/"
        self.api_key = os.getenv("TRUKNO_API_KEY")
        if not self.api_key:
            raise ValueError("TRUKNO_API_KEY not found in environment variables")
        print(f"Initialized with base URL: {self.base_url}")

    def list_breaches(self, limit: int = 10) -> Optional[List[Dict]]:
        """List recent breaches"""
        try:
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
                "Accept": "application/json"
            }
            url = f"{self.base_url}breaches/list?limit={limit}"
            print(f"Requesting URL: {url}")
            print(f"Headers: {headers}")
            
            response = requests.get(url, headers=headers, verify=True)
            print(f"Response status code: {response.status_code}")
            
            if response.status_code != 200:
                print(f"Response content: {response.text}")
                
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Failed to list breaches: {str(e)}")
            if hasattr(e, 'response') and e.response is not None:
                print(f"Status code: {e.response.status_code}")
                print(f"Response headers: {e.response.headers}")
                print(f"Response content: {e.response.text}")
            return None

    def save_response(self, response_data: Union[str, Dict], breach_id: str):
        """Save the response to a file"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"data/breach_{breach_id}_{timestamp}.json"
        
        # If response_data is a string, parse it as JSON
        if isinstance(response_data, str):
            data = json.loads(response_data)
        else:
            data = response_data
            
        # Handle if it's a list
        if isinstance(data, list) and len(data) > 0:
            data = data[0]  # Take the first object if it's a list
            
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)
        print(f"\nResponse saved to: {filename}")
        print(f"Saved data includes:")
        print(f"- Basic breach information")
        if "relatedMalwareDetails" in data:
            print(f"- {len(data['relatedMalwareDetails'])} malware details")
        if "relatedActorDetails" in data:
            print(f"- {len(data['relatedActorDetails'])} actor details")
        if "procedures" in data:
            ttp_count = sum(1 for proc in data["procedures"] if "TTPDetails" in proc)
            print(f"- {ttp_count} TTP details in procedures")

    def get_malware_details(self, malware_id: str) -> Optional[Dict]:
        """Fetch details of a specific malware by ID"""
        try:
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
                "Accept": "application/json"
            }
            url = f"{self.base_url}malware/{malware_id}"
            print(f"\nFetching malware details for ID: {malware_id}")
            print(f"Requesting URL: {url}")
            
            response = requests.get(url, headers=headers, verify=True)
            print(f"Response status code: {response.status_code}")
            
            if response.status_code != 200:
                print(f"Response content: {response.text}")
                
            response.raise_for_status()
            malware_data = response.json()
            
            # Extract only the essential fields
            essential_fields = {
                'title': malware_data.get('title'),
                'description': malware_data.get('description')
            }
            
            return essential_fields
        except requests.exceptions.RequestException as e:
            print(f"Failed to fetch malware details: {str(e)}")
            return None

    def get_actor_details(self, actor_id: str) -> Optional[Dict]:
        """Fetch details of a specific actor by ID"""
        try:
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
                "Accept": "application/json"
            }
            url = f"{self.base_url}actors/{actor_id}"
            print(f"\nFetching actor details for ID: {actor_id}")
            print(f"Requesting URL: {url}")
            
            response = requests.get(url, headers=headers, verify=True)
            print(f"Response status code: {response.status_code}")
            
            if response.status_code != 200:
                print(f"Response content: {response.text}")
                
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Failed to fetch actor details: {str(e)}")
            return None

    def get_ttp_details(self, ttp_id: str) -> Optional[Dict]:
        """Fetch details of a specific TTP by ID"""
        try:
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
                "Accept": "application/json"
            }
            url = f"{self.base_url}ttps/{ttp_id}"
            print(f"\nFetching TTP details for ID: {ttp_id}")
            print(f"Requesting URL: {url}")
            
            response = requests.get(url, headers=headers, verify=True)
            print(f"Response status code: {response.status_code}")
            
            if response.status_code != 200:
                print(f"Response content: {response.text}")
                
            response.raise_for_status()
            ttp_data = response.json()
            
            # Extract only the essential fields
            essential_fields = {
                'title': ttp_data.get('title'),
                'description': ttp_data.get('description'),
                'number': ttp_data.get('number'),
                'stage': ttp_data.get('stage')
            }
            
            return essential_fields
        except requests.exceptions.RequestException as e:
            print(f"Failed to fetch TTP details: {str(e)}")
            return None

    def get_breach_details(self, breach_id: str) -> Optional[Union[Dict, List]]:
        """Fetch details of a specific breach by ID and related information"""
        try:
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
                "Accept": "application/json"
            }
            url = f"{self.base_url}breaches/{breach_id}"
            print(f"Requesting URL: {url}")
            print(f"Headers: {headers}")
            
            response = requests.get(url, headers=headers, verify=True)
            print(f"Response status code: {response.status_code}")
            
            # Print raw response
            print("\nRaw Response:")
            print("-" * 50)
            print(response.text)
            print("-" * 50)
            
            if response.status_code != 200:
                print(f"Response content: {response.text}")
                
            response.raise_for_status()
            breach_data = response.json()
            
            # If the response is a list, take the first item
            if isinstance(breach_data, list) and len(breach_data) > 0:
                breach_data = breach_data[0]
            
            # Fetch related malware details
            if "relatedMalware" in breach_data and breach_data["relatedMalware"]:
                print(f"\nFetching details for {len(breach_data['relatedMalware'])} related malware...")
                malware_details = []
                for malware_id in breach_data["relatedMalware"]:
                    malware_info = self.get_malware_details(malware_id)
                    if malware_info:
                        malware_details.append(malware_info)
                breach_data["relatedMalwareDetails"] = malware_details
            
            # Fetch related actor details
            if "relatedActors" in breach_data and breach_data["relatedActors"]:
                print(f"\nFetching details for {len(breach_data['relatedActors'])} related actors...")
                actor_details = []
                for actor_id in breach_data["relatedActors"]:
                    actor_info = self.get_actor_details(actor_id)
                    if actor_info:
                        actor_details.append(actor_info)
                breach_data["relatedActorDetails"] = actor_details
            
            # Fetch TTP details for each procedure
            if "procedures" in breach_data and breach_data["procedures"]:
                print(f"\nFetching TTP details for {len(breach_data['procedures'])} procedures...")
                for procedure in breach_data["procedures"]:
                    if "TTP_ID" in procedure:
                        ttp_info = self.get_ttp_details(procedure["TTP_ID"])
                        if ttp_info:
                            procedure["TTPDetails"] = ttp_info
            
            # Save the complete enriched data
            self.save_response(breach_data, breach_id)
            
            return breach_data
        except requests.exceptions.RequestException as e:
            print(f"Failed to fetch breach details: {str(e)}")
            if hasattr(e, 'response') and e.response is not None:
                print(f"Status code: {e.response.status_code}")
                print(f"Response headers: {e.response.headers}")
                print(f"Response content: {e.response.text}")
                if e.response.status_code == 401:
                    print("Authentication failed. Please check your API key.")
                elif e.response.status_code == 404:
                    print("Breach not found. Please check the breach ID.")
            return None

# Example usage
if __name__ == "__main__":
    try:
        # Initialize the API client
        api = TruKnoAPI()
        
        # Try the specific breach ID
        print("\nTrying specific breach ID:")
        print("-" * 50)
        specific_id = "67dc05458f5a820fd25fd5a0 "
        breach_details = api.get_breach_details(specific_id)
        
        if breach_details:
            print("\nParsed Response (JSON):")
            print("-" * 50)
            print(json.dumps(breach_details, indent=2))
            
    except ValueError as e:
        print(f"Error: {str(e)}") 