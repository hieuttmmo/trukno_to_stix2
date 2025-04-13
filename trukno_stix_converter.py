#!/usr/bin/env python3

import json
import uuid
import datetime
import argparse
import os
from typing import Dict, List, Any, Optional, Set, Tuple

try:
    import stix2
except ImportError:
    print("Error: stix2 library not found. Please install it using: pip install stix2")
    exit(1)

try:
    from stix2patterns.validator import run_validator
    PATTERN_VALIDATOR_AVAILABLE = True
except ImportError:
    print("Warning: stix2-patterns validator not found. Pattern validation will be skipped.")
    print("To enable pattern validation, install with: pip install stix2-patterns")
    PATTERN_VALIDATOR_AVAILABLE = False

class TruKnoToSTIXConverter:
    """
    Converts TruKno API breach data to STIX 2.1 format.
    Based on the mapping defined in trukno_stix_mapping.md
    """
    
    def __init__(self, input_file: str, output_file: str = None, validate_patterns: bool = True):
        """
        Initialize the converter with input and output file paths.
        
        Args:
            input_file: Path to the TruKno JSON file
            output_file: Path to save the STIX Bundle (optional)
            validate_patterns: Whether to validate STIX patterns (default: True)
        """
        self.input_file = input_file
        self.output_file = output_file or self._generate_output_filename(input_file)
        self.trukno_data = None
        self.stix_objects = []
        self.object_refs = []  # To store references to all created objects
        self.validate_patterns = validate_patterns and PATTERN_VALIDATOR_AVAILABLE
        self.validation_results = {
            "valid_patterns": 0,
            "invalid_patterns": 0,
            "errors": []
        }
        
    def _generate_output_filename(self, input_file: str) -> str:
        """Generate an output filename based on the input filename"""
        base_path = os.path.splitext(input_file)[0]
        return f"{base_path}_stix.json"
    
    def load_trukno_data(self) -> None:
        """Load the TruKno data from the input file"""
        try:
            with open(self.input_file, 'r') as f:
                self.trukno_data = json.load(f)
            print(f"Loaded TruKno data from {self.input_file}")
        except Exception as e:
            print(f"Error loading TruKno data: {str(e)}")
            exit(1)
    
    def convert(self) -> None:
        """Convert TruKno data to STIX and create a STIX Bundle"""
        if self.trukno_data is None:
            self.load_trukno_data()
        
        # Create STIX objects according to our mapping
        self._create_identity_objects()
        self._create_attack_pattern_objects()
        self._create_malware_objects()
        self._create_threat_actor_objects()
        self._create_indicator_objects()
        self._create_vulnerability_objects()
        self._create_relationship_objects()
        self._create_report_object()
        
        # Create a STIX Bundle with all objects
        bundle = stix2.Bundle(objects=self.stix_objects)
        
        # Save to output file
        with open(self.output_file, 'w') as f:
            f.write(bundle.serialize(pretty=True))
        
        print(f"Converted TruKno data to STIX 2.1 format.")
        print(f"Created {len(self.stix_objects)} STIX objects.")
        print(f"Saved STIX Bundle to {self.output_file}")
        
        # Print pattern validation results if validation was performed
        if self.validate_patterns:
            print(f"\nPattern Validation Results:")
            print(f"  Valid patterns: {self.validation_results['valid_patterns']}")
            print(f"  Invalid patterns: {self.validation_results['invalid_patterns']}")
            
            if self.validation_results['invalid_patterns'] > 0:
                print("\nValidation errors:")
                for i, error in enumerate(self.validation_results['errors'], 1):
                    print(f"  {i}. Pattern: {error['pattern']}")
                    print(f"     Error: {error['error']}")
                    print()
    
    def _validate_stix_pattern(self, pattern: str) -> Tuple[bool, Optional[str]]:
        """
        Validate a STIX pattern using the stix2-patterns validator.
        
        Args:
            pattern: The STIX pattern to validate
            
        Returns:
            Tuple[bool, Optional[str]]: (is_valid, error_message)
        """
        if not self.validate_patterns:
            return True, None
            
        try:
            errors = run_validator(pattern)
            
            if errors:
                # Combine all errors into a single string
                error_msg = "; ".join(str(e) for e in errors)
                return False, error_msg
            return True, None
        except Exception as e:
            return False, str(e)
    
    def _create_identity_objects(self) -> None:
        """Create Identity objects for organizations and authors"""
        # Create identity for the author
        if "author" in self.trukno_data and self.trukno_data["author"]:
            author_id = f"identity--{self._generate_deterministic_uuid('author:' + self.trukno_data['author'])}"
            author = stix2.Identity(
                id=author_id,
                name=self.trukno_data["author"],
                identity_class="individual"
            )
            self.stix_objects.append(author)
            self.object_refs.append(author.id)

        # Create identities for affected industries
        if "affectedIndustries" in self.trukno_data and self.trukno_data["affectedIndustries"]:
            industries = self.trukno_data["affectedIndustries"]
            if isinstance(industries, str):
                industries = [i.strip() for i in industries.split(',')]
            
            for industry in industries:
                if not industry:
                    continue
                    
                industry_id = f"identity--{self._generate_deterministic_uuid('industry:' + industry)}"
                industry_obj = stix2.Identity(
                    id=industry_id,
                    name=industry,
                    identity_class="class",
                    sectors=[industry]
                )
                self.stix_objects.append(industry_obj)
                self.object_refs.append(industry_obj.id)
    
    def _create_attack_pattern_objects(self) -> None:
        """Create Attack Pattern objects from TTP details"""
        if "procedures" not in self.trukno_data:
            return
            
        for procedure in self.trukno_data.get("procedures", []):
            if "TTPDetails" not in procedure:
                continue
                
            ttp_details = procedure["TTPDetails"]
            
            # Skip if we don't have essential fields
            if not ttp_details.get("title"):
                continue
                
            # Set up external references if MITRE ATT&CK number exists
            external_refs = []
            if ttp_details.get("number"):
                external_refs.append({
                    "source_name": "mitre-attack",
                    "external_id": ttp_details["number"]
                })
            
            # Set up kill chain phase if stage information exists
            kill_chain_phases = []
            if ttp_details.get("stage"):
                # Extract the phase name from the stage format (e.g., "03- Initial Access")
                stage_parts = ttp_details["stage"].split('-', 1)
                if len(stage_parts) > 1:
                    phase_name = stage_parts[1].strip().lower().replace(' ', '-')
                    kill_chain_phases.append({
                        "kill_chain_name": "mitre-attack",
                        "phase_name": phase_name
                    })
            
            # Create the Attack Pattern object
            attack_pattern_id = f"attack-pattern--{self._generate_deterministic_uuid('attack-pattern:' + ttp_details['title'])}"
            attack_pattern = stix2.AttackPattern(
                id=attack_pattern_id,
                name=ttp_details["title"],
                description=ttp_details.get("description", ""),
                external_references=external_refs if external_refs else None,
                kill_chain_phases=kill_chain_phases if kill_chain_phases else None
            )
            
            self.stix_objects.append(attack_pattern)
            self.object_refs.append(attack_pattern.id)
    
    def _create_malware_objects(self) -> None:
        """Create Malware objects from malware details"""
        if "relatedMalwareDetails" not in self.trukno_data:
            return
            
        for malware_details in self.trukno_data.get("relatedMalwareDetails", []):
            # Skip if we don't have essential fields
            if not malware_details.get("title"):
                continue
                
            # Create the Malware object
            malware_id = f"malware--{self._generate_deterministic_uuid('malware:' + malware_details['title'])}"
            malware = stix2.Malware(
                id=malware_id,
                name=malware_details["title"],
                description=malware_details.get("description", ""),
                is_family=False
            )
            
            self.stix_objects.append(malware)
            self.object_refs.append(malware.id)
    
    def _create_threat_actor_objects(self) -> None:
        """Create Threat Actor objects from actor details"""
        if "relatedActorDetails" not in self.trukno_data:
            return
            
        for actor_details in self.trukno_data.get("relatedActorDetails", []):
            try:
                # Skip if we don't have essential fields
                if not actor_details.get("title"):
                    continue
                
                # Prepare description with location information
                description = actor_details.get("description", "")
                if actor_details.get("location"):
                    # Add a clear separator if there's already content in the description
                    if description:
                        description += "\n\n--------\n"
                    description += f"Location/Country of operation: {actor_details['location']}"
                
                # Create the Threat Actor object without using 'countries'
                actor_id = f"threat-actor--{self._generate_deterministic_uuid('actor:' + actor_details['title'])}"
                actor = stix2.ThreatActor(
                    id=actor_id,
                    name=actor_details["title"],
                    description=description
                    # Don't use the countries parameter as it may not be supported in all stix2 library versions
                )
                
                self.stix_objects.append(actor)
                self.object_refs.append(actor.id)
            except Exception as e:
                print(f"Warning: Failed to create Threat Actor object for '{actor_details.get('title', 'Unknown')}': {str(e)}")
                # Continue processing other actors
    
    def _create_indicator_objects(self) -> None:
        """Create Indicator objects from IOCs"""
        # Helper function to create an indicator for an IOC value
        def create_indicator(ioc_value, ioc_type, pattern_type):
            # Generate a pattern based on IOC type
            if ioc_type == "ip":
                pattern = f"[ipv4-addr:value = '{ioc_value}']"
            elif ioc_type == "domain":
                pattern = f"[domain-name:value = '{ioc_value}']"
            elif ioc_type == "md5":
                pattern = f"[file:hashes.md5 = '{ioc_value}']"
            elif ioc_type == "sha1":
                pattern = f"[file:hashes.sha1 = '{ioc_value}']"
            elif ioc_type == "sha256":
                pattern = f"[file:hashes.sha256 = '{ioc_value}']"
            else:
                return None
            
            # Validate the pattern
            is_valid, error_msg = self._validate_stix_pattern(pattern)
            
            if not is_valid:
                self.validation_results['invalid_patterns'] += 1
                self.validation_results['errors'].append({
                    'pattern': pattern,
                    'error': error_msg
                })
                print(f"Warning: Invalid STIX pattern: {pattern}")
                print(f"Error: {error_msg}")
                return None
            
            self.validation_results['valid_patterns'] += 1
                
            indicator_id = f"indicator--{self._generate_deterministic_uuid('indicator:' + ioc_value)}"
            indicator = stix2.Indicator(
                id=indicator_id,
                name=f"{ioc_type.upper()}: {ioc_value}",
                description=f"TruKno {ioc_type.upper()} indicator",
                pattern=pattern,
                pattern_type="stix",
                indicator_types=["malicious-activity"],
                valid_from=self.trukno_data.get("date") or datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")
            )
            
            return indicator
        
        # Process different types of IOCs
        for ioc_type, pattern_type in [
            ("ips", "ip"), 
            ("domains", "domain"), 
            ("hashesMd5", "md5"), 
            ("hashesSha1", "sha1"), 
            ("hashesSha256", "sha256")
        ]:
            ioc_list = []
            
            # Try to get IOCs from breach data
            if ioc_type in self.trukno_data:
                ioc_list = self.trukno_data[ioc_type]
            
            # IOCs might also be in a different location in the data structure
            elif "IOCs" in self.trukno_data and ioc_type in self.trukno_data["IOCs"]:
                ioc_list = self.trukno_data["IOCs"][ioc_type]
            
            # Convert to list if it's a string
            if isinstance(ioc_list, str):
                ioc_list = [i.strip() for i in ioc_list.split(',')]
                
            # Create indicators for each IOC
            for ioc_value in ioc_list:
                if not ioc_value:
                    continue
                    
                indicator = create_indicator(ioc_value, pattern_type, ioc_type)
                if indicator:
                    self.stix_objects.append(indicator)
                    self.object_refs.append(indicator.id)
    
    def _create_vulnerability_objects(self) -> None:
        """Create Vulnerability objects from CVEs"""
        cve_list = []
        
        # Try to get CVEs from different possible locations in the data structure
        if "cves" in self.trukno_data:
            cve_list = self.trukno_data["cves"]
        elif "IOCs" in self.trukno_data and "cves" in self.trukno_data["IOCs"]:
            cve_list = self.trukno_data["IOCs"]["cves"]
            
        # Convert to list if it's a string
        if isinstance(cve_list, str):
            cve_list = [i.strip() for i in cve_list.split(',')]
            
        # Create vulnerability objects for each CVE
        for cve_id in cve_list:
            if not cve_id:
                continue
                
            vuln_id = f"vulnerability--{self._generate_deterministic_uuid('vulnerability:' + cve_id)}"
            external_refs = [{
                "source_name": "cve",
                "external_id": cve_id
            }]
            
            vuln = stix2.Vulnerability(
                id=vuln_id,
                name=cve_id,
                external_references=external_refs
            )
            
            self.stix_objects.append(vuln)
            self.object_refs.append(vuln.id)
    
    def _create_relationship_objects(self) -> None:
        """Create Relationship objects between STIX objects"""
        # Find objects by type
        threat_actors = [obj for obj in self.stix_objects if isinstance(obj, stix2.ThreatActor)]
        malwares = [obj for obj in self.stix_objects if isinstance(obj, stix2.Malware)]
        attack_patterns = [obj for obj in self.stix_objects if isinstance(obj, stix2.AttackPattern)]
        indicators = [obj for obj in self.stix_objects if isinstance(obj, stix2.Indicator)]
        vulnerabilities = [obj for obj in self.stix_objects if isinstance(obj, stix2.Vulnerability)]
        
        # Threat Actor -> uses -> Malware
        for actor in threat_actors:
            for malware in malwares:
                rel_id = f"relationship--{self._generate_deterministic_uuid('relationship:' + actor.id + ':uses:' + malware.id)}"
                relationship = stix2.Relationship(
                    id=rel_id,
                    relationship_type="uses",
                    source_ref=actor.id,
                    target_ref=malware.id
                )
                self.stix_objects.append(relationship)
                self.object_refs.append(relationship.id)
        
        # Threat Actor -> uses -> Attack Pattern
        for actor in threat_actors:
            for attack_pattern in attack_patterns:
                rel_id = f"relationship--{self._generate_deterministic_uuid('relationship:' + actor.id + ':uses:' + attack_pattern.id)}"
                relationship = stix2.Relationship(
                    id=rel_id,
                    relationship_type="uses",
                    source_ref=actor.id,
                    target_ref=attack_pattern.id
                )
                self.stix_objects.append(relationship)
                self.object_refs.append(relationship.id)
        
        # Threat Actor -> targets -> Vulnerability
        for actor in threat_actors:
            for vuln in vulnerabilities:
                rel_id = f"relationship--{self._generate_deterministic_uuid('relationship:' + actor.id + ':targets:' + vuln.id)}"
                relationship = stix2.Relationship(
                    id=rel_id,
                    relationship_type="targets",
                    source_ref=actor.id,
                    target_ref=vuln.id
                )
                self.stix_objects.append(relationship)
                self.object_refs.append(relationship.id)
        
        # Malware -> uses -> Attack Pattern
        for malware in malwares:
            for attack_pattern in attack_patterns:
                rel_id = f"relationship--{self._generate_deterministic_uuid('relationship:' + malware.id + ':uses:' + attack_pattern.id)}"
                relationship = stix2.Relationship(
                    id=rel_id,
                    relationship_type="uses",
                    source_ref=malware.id,
                    target_ref=attack_pattern.id
                )
                self.stix_objects.append(relationship)
                self.object_refs.append(relationship.id)
        
        # Malware -> exploits -> Vulnerability
        for malware in malwares:
            for vuln in vulnerabilities:
                rel_id = f"relationship--{self._generate_deterministic_uuid('relationship:' + malware.id + ':exploits:' + vuln.id)}"
                relationship = stix2.Relationship(
                    id=rel_id,
                    relationship_type="exploits",
                    source_ref=malware.id,
                    target_ref=vuln.id
                )
                self.stix_objects.append(relationship)
                self.object_refs.append(relationship.id)
        
        # Indicator -> indicates -> Malware
        for indicator in indicators:
            for malware in malwares:
                rel_id = f"relationship--{self._generate_deterministic_uuid('relationship:' + indicator.id + ':indicates:' + malware.id)}"
                relationship = stix2.Relationship(
                    id=rel_id,
                    relationship_type="indicates",
                    source_ref=indicator.id,
                    target_ref=malware.id
                )
                self.stix_objects.append(relationship)
                self.object_refs.append(relationship.id)
        
        # Indicator -> indicates -> Attack Pattern
        for indicator in indicators:
            for attack_pattern in attack_patterns:
                rel_id = f"relationship--{self._generate_deterministic_uuid('relationship:' + indicator.id + ':indicates:' + attack_pattern.id)}"
                relationship = stix2.Relationship(
                    id=rel_id,
                    relationship_type="indicates",
                    source_ref=indicator.id,
                    target_ref=attack_pattern.id
                )
                self.stix_objects.append(relationship)
                self.object_refs.append(relationship.id)
    
    def _create_report_object(self) -> None:
        """Create the main Report object for the breach"""
        # Skip if we don't have essential fields
        if not self.trukno_data.get("title"):
            return
            
        # Set up external references
        external_refs = []
        if self.trukno_data.get("url"):
            external_refs.append({
                "source_name": self.trukno_data.get("source", "TruKno"),
                "url": self.trukno_data["url"]
            })
            
        # Create labels from affected technologies and category
        labels = []
        if "affectedTechnologies" in self.trukno_data and self.trukno_data["affectedTechnologies"]:
            if isinstance(self.trukno_data["affectedTechnologies"], str):
                technologies = [t.strip() for t in self.trukno_data["affectedTechnologies"].split(',')]
                labels.extend(technologies)
            else:
                labels.extend(self.trukno_data["affectedTechnologies"])
                
        if "category" in self.trukno_data and self.trukno_data["category"]:
            if isinstance(self.trukno_data["category"], str):
                categories = [c.strip() for c in self.trukno_data["category"].split(',')]
                labels.extend(categories)
            else:
                labels.extend(self.trukno_data["category"])
                
        # Parse the date or use current date
        published = None
        if "date" in self.trukno_data and self.trukno_data["date"]:
            try:
                # Try to parse the date in ISO format
                published = self.trukno_data["date"]
            except:
                published = datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")
        else:
            published = datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")
            
        # Create the Report object
        report_id = f"report--{self._generate_deterministic_uuid('report:' + self.trukno_data['title'])}"
        report = stix2.Report(
            id=report_id,
            name=self.trukno_data["title"],
            description=self.trukno_data.get("description", ""),
            published=published,
            labels=labels if labels else None,
            external_references=external_refs if external_refs else None,
            object_refs=self.object_refs
        )
        
        self.stix_objects.append(report)
    
    def _generate_deterministic_uuid(self, key: str) -> str:
        """
        Generate a deterministic UUID based on a key string.
        This ensures the same input key always produces the same UUID.
        """
        return str(uuid.uuid5(uuid.NAMESPACE_URL, key))


def main():
    parser = argparse.ArgumentParser(description='Convert TruKno breach data to STIX 2.1 format')
    parser.add_argument('input_file', help='Path to the TruKno JSON file')
    parser.add_argument('-o', '--output', help='Path to save the STIX Bundle (default: input_file_stix.json)')
    parser.add_argument('--no-validate', action='store_true', help='Skip pattern validation')
    
    args = parser.parse_args()
    
    converter = TruKnoToSTIXConverter(
        args.input_file, 
        args.output,
        not args.no_validate
    )
    converter.convert()


if __name__ == "__main__":
    main() 