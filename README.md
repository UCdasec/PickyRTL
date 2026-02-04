# PickyRTL

## Overview

PickyRTL is a tool for detecting CWE weaknesses in RTL code. It provides an interactive terminal interface for selecting files, parsing them, and running detection algorithms on them.

## Requirements

- Ubuntu / WSL (tested on Ubuntu 22.04)
- Python 3.10+

## Installation

1. `git clone https://github.com/UCdasec/PickyRTL.git`

## Running the Program

1. Change into the `/Detection` directory

    ```bash
    cd Detection
    ```

2. To run the program execute `./run_program.sh`

## Usage

### Parsing an HDL File

1. Start the program
2. Use the arrow keys to navigate to `Parse` and press "Enter"

    ```bash
    ---Select Mode---
      Detect
    > Parse
      Exit
    ```

3. Use the arrow keys to navigate the file explorer and select an HDL file or a folder of HDL files
4. The parsed files will be saved under `PickyRTL/Detection/Parsed_files`

### Running Detection

1. Start the program
2. Use the arrow keys to navigate to `Detect` and press "Enter"

    ```bash
    ---Select Mode---
    > Detect
      Parse
      Exit
    ```

3. Use the arrow keys to navigate the file explorer and select a parsed file or a folder of parsed files

4. When detection is finished use the arrow keys to select a save location under `PickyRTL/Detection/Results` directory

5. Enter a name for the file and press "Enter"
