# Detection

## Detection Algorithm Overview

## Limitations & Possible Improvements

- CWE-1245
    - State transitions handled across multiple case statements with the same switch variable are not handled. State transitions could be merged between the case statements
    - Switch expressions that are not a single variable are skipped for detection.
- CWE-1233
    - Security-sensitive register detection is limited by detecting registers already protected through lock bits. An improved way to identify register needing lock bit protection would be beneficial
    - Lock bit detection is limited to module inputs currently. Extending this to all registers within the module would limit detection errors that stem from the misidentification of lock bits.
- CWE-226
    - Detection of registers needing reset is dependent on CWE-1233 detection of security-sensitive registers. Gathering all registers that are reset and then matching names that are similar could be a avenue for improving this strategy
- CWE-1431
    - The "result" output of the module is the only output checked for CWE-1431 vulnerabilities. Extending this to check for leaks through other module outputs would help reduce any missed vulnerabilities
