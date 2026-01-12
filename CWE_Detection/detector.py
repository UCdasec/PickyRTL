import copy
import json
import os
import time
import tkinter as tk
from collections import defaultdict
from parser import parse
from pathlib import Path

import jellyfish
import pandas as pd
from ast_traverser import AST_Traverser
from enums import *
from file_selector import *
from InquirerPy import inquirer
from node import *
from rapidfuzz import fuzz


def load_json_file(file_path: str) -> dict:
    """Load json at specified file path

    Args:
        file_path (str): File path of json object

    Returns:
        dict: json object
    """
    parsed_json = None

    #Load JSON file
    try:
        with open(file_path, 'r') as f:
            try:
                parsed_json = json.load(f)
            except Exception as e:
                print(f"An error occurred while reading {file_path}: {e}")
    except FileNotFoundError:
        print(f"File {file_path} not found. Please check the path and try again.")
        return None
    2
    if parsed_json is None:
        print(f"Failed to load JSON from {file_path}. The file may be empty or corrupted.")
    
    return parsed_json

def save_results(CWE_1245_results_df: pd.DataFrame, CWE_1233_results_df: pd.DataFrame,  CWE_226_results_df: pd.DataFrame,  CWE_1431_results_df: pd.DataFrame, detection_statistics_df: pd.DataFrame):
    """Creates a file explorer allowing the user to select where to save the results and then saves the results at the selected location

    Args:
        CWE_1245_results_df (pd.DataFrame): CWE 1245 detection results
        CWE_1233_results_df (pd.DataFrame): CWE 1233 detection results
        CWE_226_results_df (pd.DataFrame): CWE 226 detection results
        CWE_1431_results_df (pd.DataFrame): CWE 1431 detection results
        detection_statistics_df (pd.DataFrame): Detection statistics
    """
    selected_folder_path = file_selector(
        message="---Select a folder to save the results---", 
        start_path=Path(__file__).parent.resolve() / "Results",
        save_file=True,
        file_extensions_allowed=['.json']
    )

    file_name: str = inquirer.text(
        message="Enter a name for the results"
    ).execute()
    
    save_path = os.path.join(selected_folder_path, file_name + ".xlsx")

    #Try to save file
    if save_path:
        try:
            with pd.ExcelWriter(save_path) as writer:
                CWE_1245_results_df.to_excel(writer, sheet_name="CWE 1245 Results", index=False)
                CWE_1233_results_df.to_excel(writer, sheet_name="CWE 1233 Results", index=False)
                CWE_226_results_df.to_excel(writer, sheet_name="CWE 226 Results", index=False)
                CWE_1431_results_df.to_excel(writer, sheet_name="CWE 1431 Results", index=False)
                detection_statistics_df.to_excel(writer, sheet_name="Detection Statistics", index=False)
            print(f"Results saved successfully to {save_path}")
        except Exception as e:
            print(f"Error saving file: {e}")
    else:
        print("File save operation cancelled.")

def score_name(name: str, keywords: dict) -> int:
    """Scores the name based on similarity to keywords

    Args:
        name (str): Name to score
        keywords (dict): Dictionary of keywords and their associated scores

    Returns:
        int: Total score of the name
    """
    total_score = 0
    name_lower = name.lower()
    for keyword, weight in keywords.items():
        if keyword in name_lower:
            total_score += weight
    return total_score

def detect_CWE_1245(ast_data: AST_Traverser, case_statement: HdlStmCaseNode, results: pd.DataFrame) -> pd.DataFrame:
    """Checks the case statement for CWE_1245 vulnerabilities

    Args:
        ast_data (AST_Traverser): AST data from the file
        case_statement (HdlStmCaseNode): Case statement to check for vulnerabilities
        results (pd.Dataframe): Dataframe to store the results in

    Returns:
        pd.DataFrame: Results of CWE 1245 detection
    """

    def check_state_coverage(case_statement: HdlStmCaseNode) -> str:
        """Checks if the case statement covers all possible state values

        Args:
            case_statement (HdlStmCaseNode): Case statement node to check for state coverage

        Returns:
            str: Secure if all states are covered, vulnerable if not
        """
        #Calculate the number of possible state values
        if case_statement.switch_variable_bit_width is None:
            switch_variable: HdlIdDefNode = case_statement.switch_variable
            num_possible_states = switch_variable.calculate_possible_values()
        else:
            num_possible_states = case_statement.calculate_possible_values()
        num_defined_states = len(case_statement.cases)

        if num_defined_states >= num_possible_states:
            #If the defined states cover all possible state values it is secure
            return "Secure: Defined states cover all possible values"
        elif num_defined_states < num_possible_states:
            #Possible vulnerability if number of defined states does not cover possible state values
            if case_statement.default is not None:
                #Check if the default case has an if statement and covers all possible values
                default_node: Case = case_statement.default
                if len(default_node.children) == 0:
                    return 'Secure: Default state covers rest of possible values'
                elif any(not isinstance(child_node, HdlStmIfNode) for child_node in default_node.children.values()):
                    return 'Secure: Default state covers rest of possible values'
                else:
                    for child_node in default_node.children.values():
                        #If there is an if statement in the default case check if it has a default case to cover all values
                        if isinstance(child_node, HdlStmIfNode):
                            if child_node.else_clause is not None:
                                return 'Secure: DEFAULT state covers rest of possible values'
                            else:
                                return 'Vulnerable: If statement within DEFAULT state restricts coverage of possible values'                            
            else:
                #If no default case, there is a vulnerability
                return 'Vulnerable: Not all possible values covered'
            
    def check_unreachable_states(case_statement: HdlStmCaseNode) -> str:
        """Checks case statement for unreachable states

        Args:
            case_statement (HdlStmCaseNode): Case statement to check

        Returns:
            str: Secure if no unreachable states, vulnerable if there are unreachable states, or inconclusive
        """
        assigned_to_state_variable = []

        #Handle case when the state variable is an input. 
        if case_statement.switch_variable.direction == 'IN':
            return f'Inconclusive: State variable ({case_statement.switch_variable.name}) is an input; transitions may be externally controlled and not visible in this scope'
        
        #Gather all assignments directly to the state variable
        state_variable_assignments = ast_data.variable_assignments[case_statement.switch_variable.name]
        for assignment in state_variable_assignments:
            if assignment.source not in assigned_to_state_variable:
                assignment_reachable = ast_data.determine_node_reachability(assignment)

                if assignment_reachable:
                    assigned_to_state_variable.append(assignment.source)
                    #If the assignment is reachable then the case is satisfiable
                    case_node: Case = next((v for v in case_statement.cases.values() if assignment.source in v.case_values), None)
                    if case_node:
                        case_node.satisfiable = True

        #Gather all indirect assignments to the state variable through assignments to variables assigned to the state variable
        for assignment_to_state_variable in assigned_to_state_variable:
            #Deals with when the state variable is assigned a number
            if assignment_to_state_variable not in ast_data.variable_assignments.keys():
                continue 

            assignments = ast_data.variable_assignments[assignment_to_state_variable]
            for assignment in assignments:
                if assignment.source not in assigned_to_state_variable:
                    assignment_reachable = ast_data.determine_node_reachability(assignment)

                    if assignment_reachable:
                        assigned_to_state_variable.append(assignment.source)
                        #If the assignment is reachable then the case is satisfiable
                        case_node: Case = next((v for v in case_statement.cases.values() if assignment.source in v.case_values), None)
                        if case_node:
                            case_node.satisfiable = True
        
        #Check if any states are never assigned to the state variable either directly or indirectly
        unreachable_states = []
        for case in case_statement.cases.values():
            if not(any(item in assigned_to_state_variable for item in case.case_values)):
                unreachable_states.append(case.primary_value)

        if len(unreachable_states) > 0:
            #TO_DO: Check if the state variable is mapped to another module, if so it is inconclusive as it could be updated from that module
            if case_statement.switch_variable.module_mapping:
                return f'Inconclusive: {unreachable_states} state(s) may not be reachable, but state variable is mapped to {case_statement.switch_variable.module_mapping}; transitions may be externally controlled and not visible in this scope'
            for state in unreachable_states:
                case_node = next((c for c in case_statement.cases.values() if state in c.case_values), None)
            return f'Vulnerable: {unreachable_states} state(s) not reachable'
        else:
            return 'Secure: All states reachable'

    def check_for_deadlocks(case_statement: HdlStmCaseNode) -> str:
        """Check case statements for deadlocks

        Args:
            case_statement (HdlStmCaseNode): Case statement to check

        Returns:
            str: Secure if no deadlocks, vulnerable if there are deadlocks, or inconclusive
        """
        class Transition:
            def __init__(self, start_state, next_state, assignment, condition):
                self.start_state = start_state
                self.next_state = next_state
                self.assignment = assignment
                self.condition: HdlStmIfNode = condition
                if (self.condition is None) or (self.condition.reachable and self.condition.satisfiable):
                    self.reachable = True
                else:
                    self.reachable = False

        def find_start_state(node: HdlStmAssignNode):
            """Finds start state of assignment 

            Args:
                node (HdlStmAssignNode): Assignment to find start state of

            Returns:
                Any: Returns the start state node
            """
            #Recursively search for the case and return the case primary value
            if isinstance(node, Case):
                return node.primary_value
            elif isinstance(node, HdlModuleDefNode):
                return None
            return find_start_state(ast_data.nodes[node.parent_id])

        #If the switch variable is an input we cannot see assignments so mark it as inconclusive
        if case_statement.switch_variable.direction == 'IN':
            return f'Inconclusive: State variable ({case_statement.switch_variable.name}) is an input; transitions may be externally controlled and not visible in this scope'

        state_variable_assignments = ast_data.gather_variable_assignments(case_statement.switch_variable)

        #Convert the direct and indirect state variable assignments to transitions from one state to another state
        transitions = []
        for assignment in state_variable_assignments:
            if assignment.source not in case_statement.possible_case_values:
                continue

            next_state = assignment.source
            start_state = find_start_state(node=assignment)
            transitions.append(Transition(start_state=start_state, next_state=next_state, assignment=assignment, condition=None))

        
        #Check that each state has an out transition, if so remove the state
        states = case_statement.case_primary_values.copy()
        for tr in transitions:
            if tr.start_state == tr.next_state or tr.start_state not in states:
                continue

            if tr.reachable:
                states.remove(tr.start_state)
                transitions = [t for t in transitions if t.start_state != tr.start_state]
        
        # If any states are left, there is a possible vulnerability, else there are no deadlocks      
        if len(states) > 0:
            #Remove unreachable states so they do not count as deadlocks
            for state in states:
                for case in case_statement.cases.values():
                    if state in case.case_values:
                        if not case.satisfiable:
                            states.remove(state)
                            break

            if len(states) == 0:
                return f"Secure: No deadlocks detected"
            
            #If the variable is module mapped it is inconclusive since we can't see the assignments.
            if case_statement.switch_variable.module_mapping:
                return f'Inconclusive: Possible deadlock(s) in {states} state(s), but state variable is mapped to {case_statement.switch_variable.module_mapping}; transitions may be externally controlled and not visible in this scope'
            return f"Vulnerable: Possible deadlock(s) in {states} state(s)"
        else:
            return f"Secure: No deadlocks detected"

    results[CWE_1245_RESULTS_DF_COLS.STATE_COVERAGE.value] = (check_state_coverage(case_statement))
    results[CWE_1245_RESULTS_DF_COLS.UNREACHABLE_STATES.value] = (check_unreachable_states(case_statement))
    results[CWE_1245_RESULTS_DF_COLS.DEADLOCKS.value] = (check_for_deadlocks(case_statement))

    return results

def detect_CWE_1233(file_name: str, ast_data: AST_Traverser, results: pd.DataFrame):
    """Detects two scenarios of CWE 1233 vulnerabilities in the file
    (1): Security sensitive register coverage
    (2): Lock enforcement completeness

    Args:
        file_name (str): Name of the file being detected for vulnerabilities
        ast_data (AST_Traverser): AST data from the file
        results (pd.DataFrame): Dataframe that contains the CWE 1233 detection results
    """

    def verify_security_sensitive_register_coverage(security_sensitive_register: HdlIdDefNode) -> str:
        """Scenario 1: Check if all assignments to the security sensitive register are protected with lock bits

        Args:
            security_sensitive_register (HdlIdDefNode): The security sensitive register to check for vulnerabilities

        Returns:
            str: Secure or Vulnerable with short description
        """
        assignments = ast_data.variable_assignments[security_sensitive_register.name]
        unprotected_register_assignments = []

        for assignment in assignments:
            if assignment.zeroized or assignment.source == assignment.destination or assignment.isDebugAssignment:
                #If the register is zeroized, set to itself, or is a debugging assignment it does not need to be protected by a lock bit
                continue
            elif not assignment.lock_bit_protected:
                #Assignment is not protected through lock bit
                unprotected_register_assignments.append(assignment)

        if len(unprotected_register_assignments) > 0:
            return f"Vulnerable: Assignment(s) on line {[assignment.start_line for assignment in unprotected_register_assignments]} are not protected"
        else:
            return "Secure: All assignments are protected"
        
    def verify_lock_enforcement_completeness(security_sensitive_register: HdlIdDefNode) -> str:
        """Scenario 2: Check if locked assignments correctly reject unauthorized writes

        Args:
            security_sensitive_register (HdlIdDefNode): The security sensitive register to check for vulnerabilities

        Returns:
            str: Secure or Vulnerable with short description
        """
        incorrectly_enforced_assignments = []
        assignments = ast_data.variable_assignments[security_sensitive_register.name]

        for assignment in assignments:
            if assignment.lock_bit_protected:
                #Only need to check assignments that are lock bit protected
                if assignment.zeroized or assignment.source == assignment.destination:
                    #If the register is zeroized or set to itself (write is rejected) it should be when the lock is set to 1 (when then ternary conditional is set to True)
                    parent_node = ast_data.nodes[assignment.parent_id]
                    if isinstance(parent_node, HdlStmIfNode):
                        #Lock assignment is enforced correctly
                        pass
                    elif isinstance(parent_node, Else_Clause):
                        incorrectly_enforced_assignments.append(assignment)
                else:
                    #Check to make sure that the write is only allowed when the lock bit is set to 0 (when the ternary conditional is set to False)
                    parent_node = ast_data.nodes[assignment.parent_id]
                    if isinstance(parent_node, Else_Clause):
                        #Lock assignment is enforced correctly
                        pass
                    elif isinstance(parent_node, HdlStmIfNode):
                        incorrectly_enforced_assignments.append(assignment)

        if len(incorrectly_enforced_assignments) > 0:
            return f"Vulnerable: Assignment(s) on line {[assignment.start_line for assignment in incorrectly_enforced_assignments]} are not correctly enforced and allow unauthorized writes"
        else:
            return f"Secure: All locked assignments correctly enforce and reject unauthorized writes"

    if len(ast_data.security_sensitive_registers) > 0:
        for security_sensitive_register in ast_data.security_sensitive_registers:
            new_row = {
                CWE_1233_RESULTS_DF_COLS.FILE_NAME.value: file_name,
                CWE_1233_RESULTS_DF_COLS.MODULE_NAME.value: ast_data.module_name,
                CWE_1233_RESULTS_DF_COLS.SECURITY_SENSITIVE_REGISTER.value: security_sensitive_register.name,
                CWE_1233_RESULTS_DF_COLS.ASSIGNMENT_LINE_NUMS.value: [assignment.start_line for assignment in ast_data.variable_assignments[security_sensitive_register.name]],
                CWE_1233_RESULTS_DF_COLS.LOCK_ENFORCEMENT.value: verify_lock_enforcement_completeness(security_sensitive_register),
                CWE_1233_RESULTS_DF_COLS.SECURITY_SENSITIVE_REGISTER_COVERAGE.value: verify_security_sensitive_register_coverage(security_sensitive_register),
            }
            results.loc[len(results)] = new_row
    else:
        new_row = {
            CWE_1233_RESULTS_DF_COLS.FILE_NAME.value: file_name,
            CWE_1233_RESULTS_DF_COLS.MODULE_NAME.value: ast_data.module_name,
            CWE_1233_RESULTS_DF_COLS.SECURITY_SENSITIVE_REGISTER.value: None,
            CWE_1233_RESULTS_DF_COLS.ASSIGNMENT_LINE_NUMS.value: None,
            CWE_1233_RESULTS_DF_COLS.LOCK_ENFORCEMENT.value: f"Secure: Skipped for detection, no security sensitive registers detected",
            CWE_1233_RESULTS_DF_COLS.SECURITY_SENSITIVE_REGISTER_COVERAGE.value: f"Secure: Skipped for detection, no security sensitive registers detected",
        }
        results.loc[len(results)] = new_row

def detect_CWE_226(file_name: str, ast_data: AST_Traverser, results: pd.DataFrame):
    """First determines which registers need to be reset and then ensures that the register is reset

    Args:
        file_name (str): Name of the file being detected for vulnerabilities
        ast_data (AST_Traverser): AST data from the file
        results (pd.DataFrame): Dataframe that contains the CWE 226 vulnerabilities
    """
    #Determine if any assignments in each procedural block are security sensitive registers
    #If so check for reset logic for that register
    security_sensitive_register_names = [reg.name for reg in ast_data.security_sensitive_registers]
    for procedural_block_id, proc_block_assignments in ast_data.procedural_blocks.items():
        #Determine if any registers need to be reset within the procedural block
        registers_needing_reset = set()
        reset_assignments = []
        for assignment in proc_block_assignments:
            if assignment.destination in security_sensitive_register_names:
                if assignment.zeroized and not assignment.lock_bit_protected:
                    reset_assignments.append(assignment)
                else:
                    registers_needing_reset.add(assignment.destination)

        if len(registers_needing_reset) > 0:
            #Check for reset logic within the procedural block
            for reset_assignment in reset_assignments:
                #Loop through each reset assignment to eliminate registers that need to be reset, any registers left will be considered vulnerable
                
                parent_node = ast_data.nodes[reset_assignment.parent_id]
                if isinstance(parent_node, HdlStmIfNode) or isinstance(parent_node, Else_Clause): #Check if parent is a reset condition
                    conditional_variables = ast_data.extract_conditional_variables(parent_node.condition)
                    
                    if any(not var.reset_register for var in conditional_variables):
                        #If any variable in the conditional is not a reset register it is not reset logic.
                        continue
                    elif all(var.reset_register for var in conditional_variables):
                        #If all variables in the conditional are reset registers it is reset logic, remove the register from needing reset
                        if reset_assignment.destination in registers_needing_reset:
                            registers_needing_reset.remove(reset_assignment.destination)
                            new_row = {
                                CWE_226_RESULTS_DF_COLS.FILE_NAME.value: file_name,
                                CWE_226_RESULTS_DF_COLS.MODULE_NAME.value: ast_data.module_name,
                                CWE_226_RESULTS_DF_COLS.REGISTER.value: reset_assignment.destination,
                                CWE_226_RESULTS_DF_COLS.RESET_COVERAGE.value: f"Secure: Reset logic found for {reset_assignment.destination} (Line No: {reset_assignment.start_line})",
                            }
                            results.loc[len(results)] = new_row
                            if len(registers_needing_reset) == 0:
                                break
                elif isinstance(parent_node, HdlStmProcessNode): #Check if parent is the procedural block where register needs reset
                    if parent_node.node_id == procedural_block_id:
                        registers_needing_reset.remove(reset_assignment.destination)
                        new_row = {
                            CWE_226_RESULTS_DF_COLS.FILE_NAME.value: file_name,
                            CWE_226_RESULTS_DF_COLS.MODULE_NAME.value: ast_data.module_name,
                            CWE_226_RESULTS_DF_COLS.REGISTER.value: reset_assignment.destination,
                            CWE_226_RESULTS_DF_COLS.RESET_COVERAGE.value: f"Secure: Reset logic found for {reset_assignment.destination} (Line No: {reset_assignment.start_line})",
                        }
                        results.loc[len(results)] = new_row
                        if len(registers_needing_reset) == 0:
                            break
                elif isinstance(parent_node, HdlStmForNode):
                    #TO-DO: Update to check that all bits of the register are reset through the for loop
                    #Check to make sure for loop is within reset logic
                    grandparent_node = ast_data.nodes[parent_node.parent_id]
                    if isinstance(grandparent_node, HdlStmIfNode) or isinstance(grandparent_node, Else_Clause): #Check if parent is a reset condition
                        conditional_variables = ast_data.extract_conditional_variables(grandparent_node.condition)
                        
                        if any(not var.reset_register for var in conditional_variables):
                            #If any variable in the conditional is not a reset register it is not reset logic.
                            continue
                        elif all(var.reset_register for var in conditional_variables):
                            #If all variables in the conditional are reset registers it is reset logic, remove the register from needing reset
                            if reset_assignment.destination in registers_needing_reset:
                                registers_needing_reset.remove(reset_assignment.destination)
                                new_row = {
                                    CWE_226_RESULTS_DF_COLS.FILE_NAME.value: file_name,
                                    CWE_226_RESULTS_DF_COLS.MODULE_NAME.value: ast_data.module_name,
                                    CWE_226_RESULTS_DF_COLS.REGISTER.value: reset_assignment.destination,
                                    CWE_226_RESULTS_DF_COLS.RESET_COVERAGE.value: f"Secure: Reset logic found for {reset_assignment.destination} (Line No: {reset_assignment.start_line})",
                                }
                                results.loc[len(results)] = new_row
                                if len(registers_needing_reset) == 0:
                                    break
        else:
            new_row = {
                CWE_226_RESULTS_DF_COLS.FILE_NAME.value: file_name,
                CWE_226_RESULTS_DF_COLS.MODULE_NAME.value: ast_data.module_name,
                CWE_226_RESULTS_DF_COLS.REGISTER.value: None,
                CWE_226_RESULTS_DF_COLS.RESET_COVERAGE.value: f"Secure: Skipped for detection, no registers needing reset detected",
            }
            results.loc[len(results)] = new_row                            
        for reg in registers_needing_reset:
            new_row = {
                CWE_226_RESULTS_DF_COLS.FILE_NAME.value: file_name,
                CWE_226_RESULTS_DF_COLS.MODULE_NAME.value: ast_data.module_name,
                CWE_226_RESULTS_DF_COLS.REGISTER.value: reg,
                CWE_226_RESULTS_DF_COLS.RESET_COVERAGE.value: f"Vulnerable: No reset logic found for {reg}",
            }
            results.loc[len(results)] = new_row                    

def detect_CWE_1431(file_name: str, ast_data: AST_Traverser, results: pd.DataFrame):
    """Checks cryptographic modules for results leakage through the module output. Skips non-cryptographic modules

    Args:
        file_name (str): Name of the file being detected for vulnerabilities
        ast_data (AST_Traverser): AST data from the file
        results (pd.DataFrame): Dataframe that contains the CWE 1431 detection results
    """
    if ast_data.crypto_module:
        #1. Find the "result" output register
            #Loop through outputs and choose one that is most likely to be the crypto data output
        crypto_result_output_keyword_scores = {
            "digest": 5,
            "hash": 5,
            "result": 4,
            "cipher": 4,
            "enc": 3,
            "mac": 5,
            "data_out": 3,
            "data_o": 3,
            "out": 1,
            "o,": 1,
            "valid": -5,
            "ready": -5,
        }   
        result_output_scores = [(output, score_name(output, crypto_result_output_keyword_scores)) for output in ast_data.outputs.keys()]
        result_output_scores.sort(key=lambda x: x[1], reverse=True)
        result_output = result_output_scores[0][0]

        #2. Find the "result_valid" output register
        remaining_module_outputs = copy.copy(ast_data.outputs)
        remaining_module_outputs.pop(result_output)
        crypto_valid_output_keyword_scores = {
            "digest_valid": 5,
            "hash_valid": 5,
            "data_out_valid": 5,
            "result_valid": 5,
            "valid": 4,
        }
        valid_signal_scores = [(output, score_name(output, crypto_valid_output_keyword_scores)) for output in remaining_module_outputs.keys()]
        valid_signal_scores.sort(key=lambda x: x[1], reverse=True)
        valid_signal = valid_signal_scores[0][0] if len(valid_signal_scores) > 0 else None

        valid_signal_scores = [(output, score_name(output, crypto_valid_output_keyword_scores)) for output in ast_data.variables.keys()]
        valid_signal_scores.sort(key=lambda x: x[1], reverse=True)
        highest_score = valid_signal_scores[0][1]
        possible_valid_signals = []
        for s in valid_signal_scores:
            if s[1] == highest_score:
                possible_valid_signals.append(s[0])
            else:
                break
        # If valid signal is none, either it has implemented logic other ways or it is vulnerable

        #3. Check that assignments to register from #1 are only made when register from #2 indicates a valid output
        result_output_assignments = ast_data.variable_assignments[result_output]
        vulnerable_assignments = []
        #Loop though assignments and keep track fo assignments not gated by the valid signal
        for assignment in result_output_assignments:
            print()
            print(f"Source type: {type(assignment.source)}")
            print(f"Destination type: {type(assignment.destination)}")
            print()
            #Now check that assignment is gated with logic to ensure it is valid
            parent_node = ast_data.nodes[assignment.parent_id]
            if isinstance(parent_node, HdlStmIfNode):
                condition_variables = ast_data.extract_conditional_variables(parent_node.condition)

                #Check that one of the possible valid signals is in the conditional
                if not any(var.name in possible_valid_signals for var in condition_variables):
                    #Check to ensure assignment source is not a predefined integer value (eliminates FPs originating form resets)
                    if not isinstance(assignment.source, int):
                        vulnerable_assignments.append(assignment)
            else:
                if not isinstance(assignment.source, int):
                    #If the source is a variable and not a predefined integer value, it is vulnerable
                    vulnerable_assignments.append(assignment)

        if len(vulnerable_assignments) > 0:
            new_row = {
                CWE_1431_RESULTS_DF_COLS.FILE_NAME.value: file_name,
                CWE_1431_RESULTS_DF_COLS.MODULE_NAME.value: ast_data.module_name,
                CWE_1431_RESULTS_DF_COLS.RESULT_OUTPUT.value: result_output,
                CWE_1431_RESULTS_DF_COLS.INTERMEDIATE_RESULTS_LEAKAGE.value: f"Vulnerable: '{result_output}' is assigned before result is valid",
            }
            results.loc[len(results)] = new_row 
        else:
            new_row = {
                CWE_1431_RESULTS_DF_COLS.FILE_NAME.value: file_name,
                CWE_1431_RESULTS_DF_COLS.MODULE_NAME.value: ast_data.module_name,
                CWE_1431_RESULTS_DF_COLS.RESULT_OUTPUT.value: result_output,
                CWE_1431_RESULTS_DF_COLS.INTERMEDIATE_RESULTS_LEAKAGE.value: f"Secure: '{result_output}' assignments are gated with valid logic",
            }
            results.loc[len(results)] = new_row 
            
    else:
        #Skip for non-cryptographic modules
        new_row = {
            CWE_1431_RESULTS_DF_COLS.FILE_NAME.value: file_name,
            CWE_1431_RESULTS_DF_COLS.MODULE_NAME.value: ast_data.module_name,
            CWE_1431_RESULTS_DF_COLS.RESULT_OUTPUT.value: None,
            CWE_1431_RESULTS_DF_COLS.INTERMEDIATE_RESULTS_LEAKAGE.value: f"Secure: Skipped for detection, not a cryptographic module",
        }
        results.loc[len(results)] = new_row   

def run_detection_on_file(file_path: str) -> pd.DataFrame:
    """Runs vulnerability detection on the file at the file path

    Args:
        file_path (str): File path of file for detection

    Returns:
        tuple (pd.Dataframe, pd.Dataframe, pd.Dataframe): First dataframe contains CWE 1245 detection results, second dataframe contains CWE 1233 detection results, third dataframe contains detailed results, fourth dataframe contains detection statistics
    """
    start_time = time.perf_counter()
    file_name = os.path.basename(file_path)

    CWE_1245_results_df = pd.DataFrame(columns=[col.value for col in CWE_1245_RESULTS_DF_COLS])
    CWE_1233_results_df = pd.DataFrame(columns=[col.value for col in CWE_1233_RESULTS_DF_COLS])
    CWE_226_results_df = pd.DataFrame(columns=[col.value for col in CWE_226_RESULTS_DF_COLS])
    CWE_1431_results_df = pd.DataFrame(columns=[col.value for col in CWE_1431_RESULTS_DF_COLS])
    detection_statistics_df = pd.DataFrame(columns=[col.value for col in DETECTION_STATISTICS_DF_COLS])

    #Load JSON and traverse
    json_data = load_json_file(file_path)
    for module in json_data:
        if module.get("__class__", None) == "HdlModuleDef":
            traverser = AST_Traverser()
            traverser.traverse(module, None)

            # Loop through unsatisfiable conditionals to see if they are now satisfiable
            unsatisfiable_conditionals = copy.deepcopy(traverser.unsatisfiable_conditionals)
            for cond in unsatisfiable_conditionals.values():
                if traverser.determine_conditional_satisfiability(conditional_node=cond):
                    traverser.satisfiable_conditionals[cond.node_id] = cond
                    traverser.unsatisfiable_conditionals.pop(cond.node_id)
            del unsatisfiable_conditionals

            #CWE 1245 Detection
            if len(traverser.case_statements) == 0:
                #If there are no case statements return the one row 
                CWE_1245_results_df = pd.concat([CWE_1245_results_df, pd.DataFrame([{
                    CWE_1245_RESULTS_DF_COLS.FILE_NAME.value: file_name,
                    CWE_1245_RESULTS_DF_COLS.MODULE_NAME.value: traverser.module_name,
                    CWE_1245_RESULTS_DF_COLS.CASE_NUMBER.value: 'No case statements found',
                    CWE_1245_RESULTS_DF_COLS.STATE_COVERAGE.value: None,
                    CWE_1245_RESULTS_DF_COLS.UNREACHABLE_STATES.value: None,
                    CWE_1245_RESULTS_DF_COLS.DEADLOCKS.value: None,
                }])], ignore_index=True)
            else:
                case_num = 1
                #Loop through each case statement and run detection
                for case in traverser.case_statements.values():
                    results_row = {
                        CWE_1245_RESULTS_DF_COLS.FILE_NAME.value: file_name,
                        CWE_1245_RESULTS_DF_COLS.MODULE_NAME.value: traverser.module_name,
                        CWE_1245_RESULTS_DF_COLS.CASE_NUMBER.value: case_num,
                        CWE_1245_RESULTS_DF_COLS.STATE_COVERAGE.value: None,
                        CWE_1245_RESULTS_DF_COLS.UNREACHABLE_STATES.value: None,
                        CWE_1245_RESULTS_DF_COLS.DEADLOCKS.value: None,
                    }
                    detect_CWE_1245(ast_data=traverser, case_statement=case, results=results_row)

                    #Concat current results and new results row
                    CWE_1245_results_df = pd.concat([CWE_1245_results_df, pd.DataFrame([results_row])], ignore_index=True)
                    case_num += 1
            
            #CWE 1233 Detection
            detect_CWE_1233(file_name=file_name, ast_data=traverser, results=CWE_1233_results_df)

            #CWE-226 Detection
            detect_CWE_226(file_name=file_name, ast_data=traverser, results=CWE_226_results_df)

            #CWE-1431 Detection
            detect_CWE_1431(file_name=file_name, ast_data=traverser, results=CWE_1431_results_df)

            #Calculate end of detection time here and assign to rows in each dataframe
            end_time = time.perf_counter()
            detection_time = end_time - start_time
            detection_statistics_df = pd.concat([
                detection_statistics_df,
                pd.DataFrame([{
                    DETECTION_STATISTICS_DF_COLS.FILE_NAME.value: file_name,
                    DETECTION_STATISTICS_DF_COLS.MODULE_NAME.value: traverser.module_name,
                    DETECTION_STATISTICS_DF_COLS.LINES_OF_CODE.value: traverser.loc,
                    DETECTION_STATISTICS_DF_COLS.DETECTION_TIME.value: detection_time
                }])
            ], ignore_index=True)

    return CWE_1245_results_df, CWE_1233_results_df, CWE_226_results_df, CWE_1431_results_df, detection_statistics_df

def run_detection_on_folder(folder_path: str) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """Runs vulnerability detection on each file in the folder at the specified path. Runs detection after traversal of all files so security sensitive registers and lock bti registers can be checked against one another

    Args:
        folder_path (str): Folder to run detection on

    Returns:
        tuple (pd.Dataframe, pd.Dataframe, pd.Dataframe): First dataframe contains CWE 1245 detection results,
            second dataframe contains CWE 1233 detection results,
            third dataframe contains detailed results,
            fourth dataframe contains detection statistics
    """
    def ask_matching_mode():
        """Allows user to select which matching mode"""

        matching_choice = inquirer.select(
            message="Choose a matching method for matching security sensitive registers",
            choices=['Fuzzy', 'Direct']    
        ).execute()

        match matching_choice:
            case "Direct":
                return "direct", None
            case "Fuzzy":
                threshold = inquirer.number(
                    message="Enter a threshold for matching (0-100)",
                    min_allowed=0,
                    max_allowed=100,
                    default=80
                ).execute()
                return "fuzzy", float(threshold)

    def fuzzy_matching(query: str, words: list[str], threshold: float) -> bool:
        """Check if the query string is a fuzzy match to any word in a list

        Args:
            query (str): String to try and match
            words (list[str]): Words to compare against
            threshold (int): Minimum similarity score required (0-100) required to consider a match.

        Returns:
            bool: Returns true if query is a fuzzy match to any of the words, False if not
        """
        for word in words:
            score = fuzz.ratio(query, word)
            # score = fuzz.partial_ratio(query, word)
            # score = fuzz.token_sort_ratio(query, word)
            # score = fuzz.token_set_ratio(query, word)
            # score = fuzz.WRatio(query, word)
            # score = jellyfish.jaro_similarity(query, word) * 100 #Returns a score between 0 and 1
            # score = jellyfish.jaro_winkler_similarity(query, word) * 100 #Returns a score between 0 and 1
            if score >= threshold:
                return True
        return False

    CWE_1245_results_df = pd.DataFrame(columns=[col.value for col in CWE_1245_RESULTS_DF_COLS])
    CWE_1233_results_df = pd.DataFrame(columns=[col.value for col in CWE_1233_RESULTS_DF_COLS])
    CWE_226_results_df = pd.DataFrame(columns=[col.value for col in CWE_226_RESULTS_DF_COLS])
    CWE_1431_results_df = pd.DataFrame(columns=[col.value for col in CWE_1431_RESULTS_DF_COLS])
    detection_statistics_df = pd.DataFrame(columns=[col.value for col in DETECTION_STATISTICS_DF_COLS])

    #Parse the AST for each file
    parsed_AST_data_dict = {} #Store the parsed AST data with file name as the key and parsed AST data as value
    security_registers = defaultdict(set)
    for file_name in os.listdir(folder_path):
        start_time_parsing = time.perf_counter()
        file_path = os.path.join(folder_path, file_name)

        #Load JSON and traverse the file
        json_data = load_json_file(file_path=file_path)
        for module in json_data:
            if module.get("__class__", None) == "HdlModuleDef":
                traverser = AST_Traverser()
                traverser.traverse(module, None)

                #Loop through unsatisfiable conditionals to see if they are now satisfiable
                unsatisfiable_conditionals = copy.deepcopy(traverser.unsatisfiable_conditionals)
                for cond in unsatisfiable_conditionals.values():
                    if traverser.determine_conditional_satisfiability(conditional_node=cond):
                        traverser.satisfiable_conditionals[cond.node_id] = cond
                        traverser.unsatisfiable_conditionals.pop(cond.node_id)
                del unsatisfiable_conditionals

                #Add identified security sensitive register names and lock bit register names for matching later
                for reg in traverser.security_sensitive_registers:
                    security_registers["security-sensitive-registers"].add(reg.name)
                
                for reg in traverser.lock_bit_registers:
                    security_registers["lock-bit-registers"].add(reg.name)

                parsed_AST_data_dict[(file_name, traverser.module_name)] = traverser

                end_time_parsing = time.perf_counter()
                parsing_duration = end_time_parsing - start_time_parsing
                detection_statistics_df = pd.concat([
                    detection_statistics_df,
                    pd.DataFrame([{
                        DETECTION_STATISTICS_DF_COLS.FILE_NAME.value: file_name,
                        DETECTION_STATISTICS_DF_COLS.MODULE_NAME.value: traverser.module_name,
                        DETECTION_STATISTICS_DF_COLS.LINES_OF_CODE.value: traverser.loc,
                        DETECTION_STATISTICS_DF_COLS.DETECTION_TIME.value: parsing_duration
                }])], ignore_index=True)

    matching_choice, threshold = ask_matching_mode()

    #Match identified register lock bits to any variables to find unidentified lock bits
    for (file_name, module_name), ast_data in parsed_AST_data_dict.items():
        start_time_lock_bit_matching = time.perf_counter()
        for var in ast_data.variables.values():
            #If the variable has already been identified or it is not an input we don't need to check it
            if var.possible_lock_bit_register or var.direction != "IN":
                continue

            if matching_choice == "fuzzy":
                #FUZZY MATCHING
                if fuzzy_matching(var.name, list(security_registers['lock-bit-registers']), threshold):
                    # print(f"{var.name} added as a lock bit register for {file_name}")
                    security_registers['lock-bit-registers'].add(var.name)
                    var.possible_lock_bit_register = True
                    ast_data.lock_bit_registers.append(var)
            elif matching_choice == "direct":
                #DIRECT NAME MATCHING
                if var.name in security_registers['lock-bit-registers']:
                    var.possible_lock_bit_register = True
                    ast_data.lock_bit_registers.append(var)
                
            #TO-DO check conditionals involving the lock bit to find security sensitive registers if it is a match
        
        end_time_lock_bit_matching = time.perf_counter()
        lock_bit_matching_duration = end_time_lock_bit_matching - start_time_lock_bit_matching
        detection_statistics_df.loc[detection_statistics_df[DETECTION_STATISTICS_DF_COLS.FILE_NAME.value] == file_name, DETECTION_STATISTICS_DF_COLS.DETECTION_TIME.value] += lock_bit_matching_duration

    #Match variables in each file to the list of known security sensitive and lock bit registers
    for (file_name, module_name), ast_data in parsed_AST_data_dict.items():
        start_time_security_sensitive_register_matching = time.perf_counter()
        for var in ast_data.variables.values():
            #If variable has been identified as security sensitive or a lock bit we don't need to double check
            if var.security_sensitive or var.direction == "IN":
                continue

            if matching_choice == "fuzzy":
                #FUZZY MATCHING
                if fuzzy_matching(var.name, list(security_registers['security-sensitive-registers']), threshold):
                    #I think I should check fi the variable has any assignments
                    if len(ast_data.variable_assignments[var.name]) > 0:
                        security_registers['security-sensitive-registers'].add(var.name)
                        var.security_sensitive = True
                        ast_data.security_sensitive_registers.append(var)
            elif matching_choice == "direct":
                #DIRECT MATCHING
                if var.name in security_registers['security-sensitive-registers']:
                    if len(ast_data.variable_assignments[var.name]) > 0:
                        var.security_sensitive = True
                        ast_data.security_sensitive_registers.append(var)
        
        end_time_security_sensitive_register_matching = time.perf_counter()
        security_sensitive_register_matching_duration = end_time_security_sensitive_register_matching - start_time_security_sensitive_register_matching
        detection_statistics_df.loc[detection_statistics_df[DETECTION_STATISTICS_DF_COLS.FILE_NAME.value] == file_name, DETECTION_STATISTICS_DF_COLS.DETECTION_TIME.value] += security_sensitive_register_matching_duration

    #Detection
    for (file_name, module_name), ast_data in parsed_AST_data_dict.items():
        detection_start_time = time.perf_counter()

        #CWE-1245 Detection
        if len(ast_data.case_statements) == 0:
            #If there are no case statements return the one row 
            CWE_1245_results_df = pd.concat([CWE_1245_results_df, pd.DataFrame([{
                CWE_1245_RESULTS_DF_COLS.FILE_NAME.value: file_name,
                CWE_1245_RESULTS_DF_COLS.MODULE_NAME.value: module_name,
                CWE_1245_RESULTS_DF_COLS.CASE_NUMBER.value: 'No case statements found',
                CWE_1245_RESULTS_DF_COLS.STATE_COVERAGE.value: None,
                CWE_1245_RESULTS_DF_COLS.UNREACHABLE_STATES.value: None,
                CWE_1245_RESULTS_DF_COLS.DEADLOCKS.value: None,
            }])], ignore_index=True)
        else:
            case_num = 1
            #Loop through each case statement and run detection
            for case in ast_data.case_statements.values():
                results_row = {
                    CWE_1245_RESULTS_DF_COLS.FILE_NAME.value: file_name,
                    CWE_1245_RESULTS_DF_COLS.MODULE_NAME.value: module_name,
                    CWE_1245_RESULTS_DF_COLS.CASE_NUMBER.value: case_num,
                    CWE_1245_RESULTS_DF_COLS.STATE_COVERAGE.value: None,
                    CWE_1245_RESULTS_DF_COLS.UNREACHABLE_STATES.value: None,
                    CWE_1245_RESULTS_DF_COLS.DEADLOCKS.value: None,
                }
                detect_CWE_1245(ast_data=ast_data, case_statement=case, results=results_row)

                #Concat current results and new results row
                CWE_1245_results_df = pd.concat([CWE_1245_results_df, pd.DataFrame([results_row])], ignore_index=True)
                case_num += 1

        #CWE-1233 Detection
        detect_CWE_1233(file_name=file_name, ast_data=ast_data, results=CWE_1233_results_df)

        #CWE-226 Detection
        detect_CWE_226(file_name=file_name, ast_data=ast_data, results=CWE_226_results_df)

        #CWE-1431 Detection
        detect_CWE_1431(file_name=file_name, ast_data=ast_data, results=CWE_1431_results_df)

        detection_end_time = time.perf_counter()
        detection_duration = detection_end_time - detection_start_time
        detection_statistics_df.loc[detection_statistics_df[DETECTION_STATISTICS_DF_COLS.FILE_NAME.value] == file_name, DETECTION_STATISTICS_DF_COLS.DETECTION_TIME.value] += detection_duration

    return CWE_1245_results_df, CWE_1233_results_df, CWE_226_results_df, CWE_1431_results_df, detection_statistics_df

def main():
    while True:
        mode_select = inquirer.select(
            message="---Select Mode---",
            choices=[
                "Detect",
                "Parse",
                "Exit"
            ]
        ).execute()

        match mode_select:
            case "Detect":
                selected_path = file_selector(
                    start_path=Path(__file__).parent.resolve() / "Parsed_Files",
                    message="---Select a folder or file for detection---",
                    file_extensions_allowed=['.json']
                )
                print(selected_path)

                #Run folder or file detection based on selected path
                if os.path.isdir(selected_path):
                    CWE_1245_results_df, CWE_1233_results_df, CWE_226_results_df, CWE_1431_results_df, detection_statistics_df = run_detection_on_folder(selected_path)
                elif os.path.isfile(selected_path):
                    CWE_1245_results_df, CWE_1233_results_df, CWE_226_results_df, CWE_1431_results_df, detection_statistics_df = run_detection_on_file(selected_path)
                else:
                    print("Invalid selection. Please select a valid file or folder.")
                    return
                
                #Create a row to contain the totals for CWE 1245 results
                CWE_1245_total_row = pd.DataFrame([{
                    CWE_1245_RESULTS_DF_COLS.FILE_NAME.value: 'Total',
                    CWE_1245_RESULTS_DF_COLS.CASE_NUMBER.value: CWE_1245_results_df[CWE_1245_RESULTS_DF_COLS.CASE_NUMBER.value].count(),
                    CWE_1245_RESULTS_DF_COLS.STATE_COVERAGE.value: {
                        'Secure': CWE_1245_results_df[CWE_1245_RESULTS_DF_COLS.STATE_COVERAGE.value].str.startswith('Secure').sum(),
                        'Vulnerable': CWE_1245_results_df[CWE_1245_RESULTS_DF_COLS.STATE_COVERAGE.value].str.startswith('Vulnerable').sum(),
                        'Inconclusive': CWE_1245_results_df[CWE_1245_RESULTS_DF_COLS.STATE_COVERAGE.value].str.startswith('Inconclusive').sum()
                    },
                    CWE_1245_RESULTS_DF_COLS.UNREACHABLE_STATES.value: {
                        'Secure': CWE_1245_results_df[CWE_1245_RESULTS_DF_COLS.UNREACHABLE_STATES.value].str.startswith('Secure').sum(),
                        'Vulnerable': CWE_1245_results_df[CWE_1245_RESULTS_DF_COLS.UNREACHABLE_STATES.value].str.startswith('Vulnerable').sum(),
                        'Inconclusive': CWE_1245_results_df[CWE_1245_RESULTS_DF_COLS.UNREACHABLE_STATES.value].str.startswith('Inconclusive').sum()
                    },
                    CWE_1245_RESULTS_DF_COLS.DEADLOCKS.value: {
                        'Secure': CWE_1245_results_df[CWE_1245_RESULTS_DF_COLS.DEADLOCKS.value].str.startswith('Secure').sum(),
                        'Vulnerable': CWE_1245_results_df[CWE_1245_RESULTS_DF_COLS.DEADLOCKS.value].str.startswith('Vulnerable').sum(),
                        'Inconclusive': CWE_1245_results_df[CWE_1245_RESULTS_DF_COLS.DEADLOCKS.value].str.startswith('Inconclusive').sum()
                    },
                }])
                CWE_1245_results_df = pd.concat([CWE_1245_results_df, CWE_1245_total_row], ignore_index=True)

                save_results(CWE_1245_results_df, CWE_1233_results_df, CWE_226_results_df, CWE_1431_results_df, detection_statistics_df)
            case "Parse":
                parse()
            case "Exit":
                print("Goodbye")
                break

if __name__ == "__main__":
    main()