from enum import Enum


class CWE_1245_RESULTS_DF_COLS(Enum):
    FILE_NAME = "File Name"
    MODULE_NAME = "Module Name"
    CASE_STMT_STATE_VARIABLE = "Case Statement State Variable"
    CASE_STMT_START_LINE = "Case Statement Start Line"
    STATE_COVERAGE = "State Coverage"
    UNREACHABLE_STATES = "Unreachable States"
    DEADLOCKS = "Deadlocks"

class CWE_1233_RESULTS_DF_COLS(Enum):
    FILE_NAME = "File Name"
    MODULE_NAME = "Module Name"
    SECURITY_SENSITIVE_REGISTER = "Security Sensitive Register"
    ASSIGNMENT_LINE_NUMS = "Assignment Line Numbers"
    LOCK_ENFORCEMENT = "Lock Enforcement"
    SECURITY_SENSITIVE_REGISTER_COVERAGE = "Security Sensitive Register Coverage"

class CWE_226_RESULTS_DF_COLS(Enum):
    FILE_NAME = "File Name"
    MODULE_NAME = "Module Name"
    REGISTER = "Register"
    RESET_COVERAGE = "Reset Coverage"

class CWE_1431_RESULTS_DF_COLS(Enum):
    FILE_NAME = "File Name"
    MODULE_NAME = "Module Name"
    RESULT_OUTPUT = "Result Output"
    INTERMEDIATE_RESULTS_LEAKAGE = "Intermediate State/Results Leakage"

class DETECTION_STATISTICS_DF_COLS(Enum):
    FILE_NAME = "File Name"
    MODULE_NAME = "Module Name"
    LINES_OF_CODE = "LoC"
    DETECTION_TIME = "Detection Time"