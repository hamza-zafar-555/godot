import pandas as pd
import json
import re

# Ensure the column names match your actual CSV files' column names
TECHNIQUE_NAME_COLUMN = 'Mappings'  # Replace 'Name' with the actual column name for techniques in CAPEC.csv
RELATED_WEAKNESSES_COLUMN = 'Related Weaknesses'  # This should match the column name in CAPEC.csv that relates to CWE

def find_techniques(cwe, capec_df):
    pattern = rf"(^|,){re.escape(cwe)}(,|$)"
    matching_techniques = capec_df[capec_df[RELATED_WEAKNESSES_COLUMN].str.contains(pattern, na=False)]
    return matching_techniques[[TECHNIQUE_NAME_COLUMN, 'Mappings']].to_dict('records')

def find_nist_mappings(techniques_details, nist_mitre_df):
    nist_mappings = []
    for technique in techniques_details:
        if 'Mappings' in technique:  # Check if 'Mappings' key exists to avoid KeyError
            # Ensure that 'Mappings' is a string before attempting to split
            if isinstance(technique['Mappings'], str):
                technique_ids = technique['Mappings'].split(',')
                for tech_id in technique_ids:
                    matches = nist_mitre_df[nist_mitre_df['Technique ID'].str.contains(rf"(^|,){re.escape(tech_id)}(,|$)", na=False)]
                    nist_mappings.extend(matches['Control ID'].tolist())
    return nist_mappings


def find_industrial_mappings(nist_controls, nist_industry_df):
    industrial_mappings = []
    for control_id in nist_controls:
        matches = nist_industry_df[nist_industry_df['NIST SP 800-53 Rev. 5 Control'] == control_id]
        for _, row in matches.iterrows():
            mapping = {col: row[col] for col in matches.columns}
            industrial_mappings.append(mapping)
    return industrial_mappings

def main(cve_id):
    # Replace these file paths with the correct paths where your CSV and XLSX files are located
    cves_df = pd.read_csv('CVEs.csv')
    capec_df = pd.read_csv('CAPEC.csv')
    nist_mitre_df = pd.read_excel('NIST vs MITRE.xlsx')
    nist_industry_df = pd.read_csv('NIST_Industry.csv')

    cve_row = cves_df[cves_df['CVE ID'] == cve_id]
    if cve_row.empty:
        return "CVE ID not found."
    cwe = cve_row.iloc[0]['CWE']

    techniques_details = find_techniques(cwe, capec_df)
    nist_controls = find_nist_mappings(techniques_details, nist_mitre_df)
    industrial_mappings = find_industrial_mappings(nist_controls, nist_industry_df)

    data_structure = {
        "CVE ID": cve_id,
        "Techniques": [tech[TECHNIQUE_NAME_COLUMN] for tech in techniques_details],
        "NIST Controls": nist_controls,
        "Industrial Controls Mappings": industrial_mappings
    }

    with open(f"{cve_id}_mappings.json", 'w') as json_file:
        json.dump(data_structure, json_file, indent=4)

    return f"Data for {cve_id} has been processed and saved."

if __name__ == "__main__":
    user_input_cve_id = input("Enter CVE ID: ").strip()
    print(main(user_input_cve_id))
