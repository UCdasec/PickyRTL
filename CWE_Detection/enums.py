from enum import Enum

class CWE_1245_RESULTS_DF_COLS(Enum):
    FILE_NAME = "File Name"
    CASE_NUMBER = "Case Number"
    STATE_COVERAGE = "State Coverage"
    UNREACHABLE_STATES = "Unreachable States"
    DEADLOCKS = "Deadlocks"

class CWE_1233_RESULTS_DF_COLS(Enum):
    FILE_NAME = "File Name"
    SECURITY_SENSITIVE_REGISTER = "Security Sensitive Register"
    ASSIGNMENT_LINE_NUMS = "Assignment Line Numbers"
    LOCK_ENFORCEMENT = "Lock Enforcement"
    SECURITY_SENSITIVE_REGISTER_COVERAGE = "Security Sensitive Register Coverage"

class CWE_226_RESULTS_DF_COLS(Enum):
    FILE_NAME = "File Name"
    REGISTER = "Register"
    RESET_COVERAGE = "Reset Coverage"

class DETECTION_STATISTICS_DF_COLS(Enum):
    FILE_NAME = "File Name"
    LINES_OF_CODE = "LoC"
    DETECTION_TIME = "Detection Time"