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
