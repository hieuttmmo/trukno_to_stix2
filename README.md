# TruKno to STIX 2.1 Converter

This toolkit converts TruKno API breach data to STIX 2.1 format, implementing the mapping defined in `trukno_stix_mapping.md`. It includes tools for fetching data from the TruKno API, processing multiple breach IDs, and converting the data to standardized STIX format for use in other security systems.

## ✅ Project Status

All components have been successfully implemented and tested:

- ✅ TruKno API client working correctly
- ✅ STIX converter handling all object types
- ✅ Batch processing tool working as expected
- ✅ Pattern validation implemented
- ✅ Error handling and recovery in place

## Features

- Fetches breach data from TruKno API including related entities
- Saves raw JSON responses for reference
- Converts TruKno breach data to STIX 2.1 bundle format
- Maps breach details to STIX Report objects
- Maps TTP details to STIX Attack Pattern objects
- Maps malware details to STIX Malware objects
- Maps actor details to STIX Threat Actor objects
- Maps IOCs to STIX Indicator objects
- Maps CVEs to STIX Vulnerability objects
- Creates appropriate STIX relationships between objects
- Validates STIX patterns using the OASIS STIX Pattern Validator
- Batch processing of multiple TruKno breach IDs
- Organizes output in timestamped directories
- Maintains persistent ID mappings via SQLite database to ensure object consistency

## Installation

1. Clone this repository
2. Install the required dependencies:

```bash
pip install -r requirements.txt
```

3. Set your TruKno API key as an environment variable:

```bash
export TRUKNO_API_KEY="your_api_key_here"
```

Alternatively, you can provide the API key directly when using the batch processing script.

## Usage

### Fetching Data Directly with TruKno API

```bash
# Import the TruKnoAPI class in your script
from trukno_api import TruKnoAPI

# Initialize the client
api = TruKnoAPI()

# Fetch breach details
breach_data = api.get_breach_details("breach_id_here")
```

### Converting a Single TruKno JSON File

```bash
python trukno_stix_converter.py path/to/trukno_breach.json
```

Optional arguments:

- `-o, --output`: Specify the output file path for the STIX bundle (default: input_file_stix.json)
- `--no-validate`: Skip STIX pattern validation (useful if you want to proceed with potentially invalid patterns)
- `--db-file`: Path to SQLite database file for ID mapping (default: trukno_stix_mapping.db)

Example:

```bash
python trukno_stix_converter.py data/breach_67f7ed849653310e06650643_20250413_121641.json
```

### Processing Multiple TruKno Breach IDs

To fetch data from the TruKno API for multiple breach IDs and convert each to STIX format:

```bash
python process_trukno_ids.py breach_id1 breach_id2 breach_id3
```

Optional arguments:

- `--api-key`: Specify the TruKno API key (if not provided, uses TRUKNO_API_KEY environment variable)
- `--db-file`: Path to SQLite database file for ID mapping (default: trukno_stix_mapping.db)

Example:

```bash
python process_trukno_ids.py 67dc05458f5a820fd25fd5a0 67f7ed849653310e06650643
```

This will:
1. Create a timestamped directory under `data/` (e.g., `data/trukno_run_20250415_143022/`)
2. For each breach ID:
   - Fetch the data using the TruKno API
   - Save the raw JSON data
   - Convert it to STIX 2.1 format
   - Save the STIX data
3. Each breach ID gets its own subdirectory with both raw and STIX files

## Output Structure

```
data/
└── trukno_run_20250413_130141/
    ├── 67dc05458f5a820fd25fd5a0/
    │   ├── 67dc05458f5a820fd25fd5a0_raw.json  # Raw TruKno data
    │   └── 67dc05458f5a820fd25fd5a0_stix.json # Converted STIX data
    └── 67f7ed849653310e06650643/
        ├── 67f7ed849653310e06650643_raw.json  # Raw TruKno data
        └── 67f7ed849653310e06650643_stix.json # Converted STIX data
```

## STIX Object Types

The converter generates a STIX 2.1 bundle containing:

- STIX Report object for the breach
- STIX Attack Pattern objects for TTPs
- STIX Malware objects for malware
- STIX Threat Actor objects for actors
- STIX Indicator objects for IOCs
- STIX Vulnerability objects for CVEs
- STIX Relationship objects connecting everything

## Pattern Validation

The converter includes pattern validation for STIX indicators using the [OASIS STIX Pattern Validator](https://github.com/oasis-open/cti-pattern-validator). This ensures that all generated STIX patterns conform to the STIX 2.1 specification.

When validation is enabled (the default), the converter will:

1. Check each generated pattern for syntax and semantic errors
2. Skip invalid patterns to ensure the resulting STIX bundle is valid
3. Report detailed validation results after conversion
4. Print specific error messages for debugging invalid patterns

To disable validation, use the `--no-validate` flag.

## Additional Documentation

See `trukno_stix_mapping.md` for the detailed mapping between TruKno API fields and STIX 2.1 objects.

## Persistent ID Mapping

The converter maintains a SQLite database (`trukno_stix_mapping.db` by default) to ensure consistent ID mapping between TruKno objects and STIX objects. This means that the same TruKno entity (e.g., a specific malware, actor, or CVE) will always map to the same STIX ID across different runs and conversions.

This feature is particularly useful when:
- Converting multiple breach reports that reference the same entities
- Updating existing STIX data with new information
- Ensuring consistency in STIX data across your threat intelligence ecosystem

The database schema includes separate tables for different object types:
- `identity_mapping`: Maps TruKno authors and industries to STIX Identity objects
- `attack_pattern_mapping`: Maps TruKno TTPs to STIX Attack Pattern objects
- `malware_mapping`: Maps TruKno malware to STIX Malware objects
- `threat_actor_mapping`: Maps TruKno actors to STIX Threat Actor objects
- `indicator_mapping`: Maps TruKno IOCs to STIX Indicator objects
- `vulnerability_mapping`: Maps TruKno CVEs to STIX Vulnerability objects
- `report_mapping`: Maps TruKno breaches to STIX Report objects

## Testing ID Consistency

A test script is provided to verify that the SQLite database correctly maintains ID consistency:

```bash
python test_id_consistency.py breach_id
```

This script:
1. Processes the same breach ID twice
2. Compares the STIX IDs between both runs
3. Verifies that all objects have consistent IDs
4. Provides statistics on the database content

Optional arguments:
- `--api-key`: Specify the TruKno API key (if not provided, uses TRUKNO_API_KEY environment variable)
- `--db-file`: Path to SQLite database file (default: trukno_stix_mapping.db)

Example:
```bash
python test_id_consistency.py 67dc05458f5a820fd25fd5a0
```

If the test passes successfully, you'll see a confirmation that all IDs match between runs, which indicates that the persistent ID mapping is working correctly.