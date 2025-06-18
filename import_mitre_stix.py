import json
import sqlite3
import os

MITRE_BUNDLE_PATH = 'mitre_stix_data/enterprise-attack.json'
DB_PATH = 'trukno_stix_mapping.db'

def import_mitre_stix_objects():
    if not os.path.exists(MITRE_BUNDLE_PATH):
        print(f"MITRE bundle not found at {MITRE_BUNDLE_PATH}")
        return

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS mitre_stix_objects (
            stix_id TEXT PRIMARY KEY,
            stix_type TEXT,
            name TEXT,
            aliases TEXT,
            description TEXT
        )
    ''')

    with open(MITRE_BUNDLE_PATH, 'r', encoding='utf-8') as f:
        bundle = json.load(f)
        count = 0
        for obj in bundle['objects']:
            if obj['type'] in ['attack-pattern', 'malware', 'threat-actor']:
                stix_id = obj['id']
                stix_type = obj['type']
                name = obj.get('name', '')
                aliases = ','.join(obj.get('aliases', []))
                description = obj.get('description', '')
                c.execute('''
                    INSERT OR IGNORE INTO mitre_stix_objects (stix_id, stix_type, name, aliases, description)
                    VALUES (?, ?, ?, ?, ?)
                ''', (stix_id, stix_type, name, aliases, description))
                count += 1
    conn.commit()
    conn.close()
    print(f"Imported {count} MITRE STIX objects into the database.")

if __name__ == '__main__':
    import_mitre_stix_objects()
