# TruKno to STIX 2.1 Mapping

## Overview

The STIX (Structured Threat Information Expression) 2.1 standard provides a structured format for sharing cyber threat intelligence. We'll map TruKno API data to appropriate STIX objects to ensure our converted data follows the STIX specification.

## Key STIX 2.1 Objects

Before diving into the mapping, here are the main STIX objects we'll use:

| STIX Object Type | Description | Use Case |
|------------------|-------------|----------|
| Report | A collection of threat intelligence about a specific topic | Will represent the overall breach |
| Attack Pattern | Type of TTP that describes ways adversaries attempt to compromise targets | Will represent TTP details |
| Malware | Software designed to compromise systems | Will represent malware details |
| Threat Actor | Individuals, groups, or organizations believed to operate with malicious intent | Will represent actor details |
| Relationship | Describes how objects are related to each other | Will connect objects together |
| Identity | Individuals, organizations, or groups | Will represent affected organizations/industries |
| Indicator | Pattern that can be used to detect suspicious activity | Will represent IOCs (if present) |
| Vulnerability | A weakness in a system's security | Will represent vulnerability details |

## Detailed Mapping

### Breach → STIX Report

| TruKno Field | STIX Field | Notes |
|--------------|------------|-------|
| _id | id | Will be converted to format `report--{UUID}` |
| title | name | Direct mapping |
| description | description | Direct mapping |
| date | published | Convert to STIX timestamp format |
| url | external_references[].url | Add with source_name="TruKno" |
| source | external_references[].source_name | Add to external references |
| author | created_by_ref | Convert to Identity object reference |
| affectedIndustries | object_refs | Create Identity objects for industries and reference |
| affectedTechnologies | labels | Add as labels |
| category | labels | Add as labels |

### TTP Details → STIX Attack Pattern

| TruKno Field | STIX Field | Notes |
|--------------|------------|-------|
| title | name | Direct mapping |
| description | description | Direct mapping |
| number | external_references[].external_id | Add with source_name="MITRE ATT&CK" |
| stage | kill_chain_phases[].phase_name | Add with kill_chain_name="mitre-attack" |

### Malware Details → STIX Malware

| TruKno Field | STIX Field | Notes |
|--------------|------------|-------|
| title | name | Direct mapping |
| description | description | Direct mapping |
| - | is_family | Set to "false" unless evidence suggests it's a malware family |
| - | type | Set to "malware" |

### Actor Details → STIX Threat Actor

| TruKno Field | STIX Field | Notes |
|--------------|------------|-------|
| title | name | Direct mapping |
| description | description | Direct mapping |
| location | countries | Parse location and map to country codes |

### IOCs → STIX Indicator

| TruKno Field | STIX Field | Notes |
|--------------|------------|-------|
| ips | pattern | Convert to STIX pattern format like `[ipv4-addr:value = '1.2.3.4']` |
| domains | pattern | Convert to STIX pattern format like `[domain-name:value = 'example.com']` |
| hashesMd5 | pattern | Convert to STIX pattern format like `[file:hashes.md5 = '...']` |
| hashesSha1 | pattern | Convert to STIX pattern format like `[file:hashes.sha1 = '...']` |
| hashesSha256 | pattern | Convert to STIX pattern format like `[file:hashes.sha256 = '...']` |
| - | indicator_types | Add appropriate types like "malicious-activity" |
| - | valid_from | Set to breach date or current date if not available |
| - | name | Generate based on IOC type and value |

### CVEs → STIX Vulnerability

| TruKno Field | STIX Field | Notes |
|--------------|------------|-------|
| cves (individual CVE ID) | name | Use the CVE ID as the name |
| cves (individual CVE ID) | external_references[].external_id | Add with source_name="cve" |
| - | description | If available in TruKno data, otherwise leave blank |

### Relationships

We'll create the following STIX Relationship objects to connect our objects:

1. Report → "reports" → Attack Pattern
2. Report → "reports" → Malware
3. Report → "reports" → Threat Actor
4. Report → "reports" → Indicator
5. Report → "reports" → Vulnerability
6. Threat Actor → "uses" → Malware
7. Threat Actor → "uses" → Attack Pattern
8. Threat Actor → "targets" → Vulnerability
9. Indicator → "indicates" → Threat Actor

## Implementation Considerations

1. **STIX ID Generation**: 
   - All STIX objects need unique IDs in the format `{type}--{UUID}`
   - We'll generate UUIDs based on object content for consistency

2. **Timestamps**:
   - STIX requires timestamps in RFC3339 format
   - Need to convert all date fields from TruKno

3. **Required STIX Properties**:
   - Ensure all required properties for each STIX object type are included
   - Add `type`, `id`, `created`, and `modified` to all objects

4. **Python STIX2 Library**:
   - Use the `stix2` Python library to create and validate STIX objects
   - Example: `stix2.Report(name="Title", description="Desc", ...)` 

5. **Handling Missing Data**:
   - Implement checks for missing/null values in TruKno data
   - Only create relationships for objects that exist

## Example Code Snippet

```python
import stix2
from datetime import datetime
import uuid

def convert_breach_to_stix(breach_data):
    # Create STIX Report for the breach
    report = stix2.Report(
        id=f"report--{uuid.uuid4()}",
        name=breach_data.get("title", "Unnamed Breach"),
        description=breach_data.get("description", ""),
        published=datetime.strptime(breach_data.get("date", datetime.now().isoformat()), 
                                   "%Y-%m-%dT%H:%M:%S.%fZ"),
        object_refs=[]  # Will be populated as we create objects
    )
    
    # Continue with other objects...
    
    return report
```

## References

- [STIX 2.1 Specification](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html)
- [Python STIX 2 Library](https://github.com/oasis-open/cti-python-stix2) 