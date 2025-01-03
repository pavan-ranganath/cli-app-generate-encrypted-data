# Encrypt CSV CLI Application

This CLI application encrypts each row of a CSV file and generates Proxy Re-encryption (PRE) keys for each row. It supports selective encryption where specified columns can be excluded from encryption.

## Features
- Encrypts each row using a unique key.
- Handles encryption for both string and numeric fields.
- Generates Proxy Re-encryption (PRE) keys for each encrypted row.
- Allows exclusion of specific columns from encryption.

## Prerequisites
- Node.js (v14 or later) and npm installed.

## Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/pavan-ranganath/cli-app-generate-encrypted-data.git
   cd cli-app-generate-encrypted-data
   ```

2. Install the dependencies:
   ```bash
   npm install
   ```

3. Make the script executable:
   ```bash
   chmod +x ./src/encrypt-csv.ts
   ```



## Usage
Run the CLI application with the following command:
```bash
./src/encrypt-csv.ts -i <input_csv_file> -o <output_csv_file> -k <columns_to_skip>
```

### Example
To encrypt a file named `medicalRecordSample10.csv`, skip the `PatientID` column, and save the result to `medicalRecordSample10_output.csv`, run:
```bash
./src/encrypt-csv.ts -i medicalRecordSample10.csv -k PatientID -o medicalRecordSample10_output.csv
```

## Options
- `-i, --input <path>`: Path to the input CSV file (required).
- `-o, --output <path>`: Path to save the encrypted output CSV file (required).
- `-k, --keys <columns>`: Comma-separated list of column names to skip encryption (optional).

## File Format
### Input CSV
The input file should be a valid CSV file with headers. Example:
| PatientID | Name   | Age | Diagnosis    |
|-----------|--------|-----|--------------|
| 101       | Alice  | 30  | Hypertension |
| 102       | Bob    | 45  | Diabetes     |

### Output CSV
The output file will include the encrypted fields and an additional `PRE_key` column:
| PatientID | Name               | Age                | Diagnosis                | PRE_key              |
|-----------|--------------------|--------------------|--------------------------|----------------------|
| 101       | ENCRYPTED_STRING   | ENCRYPTED_NUMBER   | ENCRYPTED_STRING         | GENERATED_PRE_KEY    |
| 102       | ENCRYPTED_STRING   | ENCRYPTED_NUMBER   | ENCRYPTED_STRING         | GENERATED_PRE_KEY    |

## Troubleshooting
- Ensure the public key file path is correctly configured in the script.
- Verify that the input CSV file exists and is correctly formatted.
- Use Node.js v14 or later for compatibility.
