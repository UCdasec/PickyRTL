# Inserting Vulnerabilities Into Example Gathered From Open-source SoC Designs

## Goal

## Workflow - Inserting Vulnerabilities into Examples


## Workflow - Gathering Files

1. Retrieve Verilog and SystemVerilog files from 'bigquery-public-data.github_repos.files'
2. Send GET request for the actual file from GitHub
3. Filter out files based on two conditions
    * Files without a module definition are filtered out
    * Files that have syntax errors are filtered out
4. Sort examples based on CWE components

## CWE Component Rules

- CWE-1245
- CWE-1233
- CWE-226
- CWE-1431

## Folder Structure

```bash
└── 📁Insert_Into_Examples
    └── 📁categorized_files #Storage for files that have been sorted by what CWE components they contain
        └── 📁CWE-1233
        └── 📁CWE-1245
        └── 📁CWE-1431
        └── 📁CWE-226
        └── 📁unsorted
    └── 📁files_with_weaknesses #Storage for files after inserting weaknesses
    └── 📁filtered_files #Files that have a module definition and no syntax errors
    └── 📁prompts
        ├── CWE-1233_prompt.txt
        ├── CWE-1245_prompt.txt
        ├── CWE-1431_prompt.txt
        ├── CWE-226_prompt.txt
    └── 📁slang
    └── 📁testing_insertion_with_ai
        └── 📁CWE-1233
        └── 📁CWE-1245
        └── 📁CWE-1431
        └── 📁CWE-226
    └── 📁unfiltered_files #Files that are retrieved from BigQuery and then downloaded from GitHub
    ├── CONFIG.py
    ├── download_files_from_bq.py
    ├── downloaded.sqlite3
    ├── filter_verilog_files.py
    ├── find_CWE_components.py
    └── README.md
```