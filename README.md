# PickyRTL

## Overview

PickyRTL – Detection is a tool for performing static security analysis on RTL (Register Transfer Level) hardware descriptions, specifically Verilog (.v) and SystemVerilog (.sv) files. The detection workflow allows users to parse HDL files and analyze them for potential hardware security vulnerabilities before fabrication, when fixes are still possible.

The tool currently detects vulnerabilities associated with:
- CWE-1245: Improper Finite State Machines (FSMs) in Hardware Logic
- CWE-1233: Security-Sensitive Hardware Controls with Missing Lock Bit Protection
- CWE-226: Sensitive Information in Resource Not Removed Before Reuse
- CWE-1431: Driving Intermediate Cryptographic State/Results to Hardware Module Outputs

## Branches

- **main**
    - Contains stable PickyRTL code for work outlined in "PickyRTL: A Static Analysis Tool for Detecting Hardware CWEs at Register-Transfer Level"
    - Detection algorithms for 
        - CWE-1245
        - CWE-1233
        - CWE-226
        - CWE-1431
- **version-2** 
    - Current working branch for improvements on PickyRTL
    - Future work includes
        - Detection algorithm improvements
        - Larger dataset generation

## Requirements

- Ubuntu / WSL (tested on Ubuntu 24.04)

## Running the Program 

1. Clone the repository
2. Navigate to the `/Detection` directory

    ```bash
    cd Detection
    ```

3. To run the program execute `./run_program.sh`

### Usage
To learn more about the functionality and capabilities of PickyRTL, visit the `/docs` folder

## Folder Structure

```bash
└── 📁PickyRTL
    └── 📁Detection
        └── 📁Examples
        └── 📁Parsed_Files
        └── 📁Results 
        ├── ast_traverser.py
        ├── enums.py
        ├── file_selector.py
        ├── main.py
        ├── node.py
        ├── parser.py
        ├── README.md
        ├── requirements.txt
        ├── run_program.sh 
    └── 📁docs #Contains helpful documentation for PickyRTL
    ├── .gitignore
    ├── README.md
    └── run_program.sh
```
