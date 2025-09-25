from enum import Enum

class CWE_1245_RESULTS_DF_COLS(Enum):
    FILE_NAME = "File Name"
    CASE_NUMBER = "Case Number"
    STATE_COVERAGE = "State Coverage"
    UNREACHABLE_STATES = "Unreachable States"
    DEADLOCKS = "Deadlocks"

class CWE_1233_RESULTS_DF_COLS(Enum):
    FILE_NAME = "File Name"
    SECURITY_SENSITIVE_REGISTERS = "Security Sensitive Registers"
    LOCK_ENFORCEMENT = "Lock Enforcement"
    SECURITY_SENSITIVE_REGISTER_COVERAGE = "Security Sensitive Register Coverage"

class DETAILED_RESULTS(Enum):
    FILE_NAME = "File Name"
    RELATED_CWE = "Related CWE"
    VULNERABILITY_TYPE = "Vulnerability Type"
    LINE_NUMBER = "Line Number"
    DESCRIPTION = "Description"


class DETECTION_STATISTICS_DF_COLS(Enum):
    FILE_NAME = "File Name"
    LINES_OF_CODE = "LoC"
    DETECTION_TIME = "Detection Time"