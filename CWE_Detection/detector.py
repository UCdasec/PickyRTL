import json
from ast_traverser import AST_Traverser
from node import *
import os
import copy
import pandas as pd
import tkinter as tk
from tkinter import filedialog
import time


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

def select_files_for_detection() -> str | None:
    """Opens dialog to select file or folder of files to run for detection

    Returns:
        str | None: File or folder path for detection or None if no path was detected
    """

    root = tk.Tk()
    root.title("Choose a file or folder") # Set the title of the window
    root.geometry("300x100")  # Set the size of the window

    def select_file(selected: dict) -> dict:
        """Opens dialog to select file for detection

        Args:
            selected (dict): Dictionary to store selected file path in

        Returns:
            dict: Contains selected file path under path
        """
        selected_path = filedialog.askopenfilename(
            title="Select a file",
            initialdir="/media/sf_Summer_Research/DetectRTL/CWE_Detection/Parsed_Files",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        if selected_path:
            selected['path'] = selected_path
            root.quit()  # Close the dialog after selection

    def select_folder(selected: dict) -> dict:
        """Opens dialog to select folder for detection

        Args:
            selected (dict): Dictionary to store selected folder path in

        Returns:
            dict: Contains selected folder path under path
        """
        selected_path = filedialog.askdirectory(
            title="Select a folder",
            initialdir="/media/sf_Summer_Research/DetectRTL/CWE_Detection/Parsed_Files"
        )
        if selected_path:
            selected['path'] = selected_path
            root.quit() #Close the dialog after selection

    selected = {}

    tk.Button(root, text="Select a file", command=lambda: select_file(selected)).pack(pady=10)
    tk.Button(root, text="Select a folder", command=lambda: select_folder(selected)).pack(pady=10)

    root.mainloop()

    # If a selection was made return the selected path
    if root.winfo_exists():
        root.destroy()
        return selected['path']
    else:
        print("No selection made. Exiting.")
        return None        

def save_results(results_df: pd.DataFrame):
    """Opens dialog to save results

    Args:
        results_df (pd.DataFrame): Results to save
    """
    root = tk.Tk()
    root.withdraw()  # Hide the root window

    # Open dialog box to save results file as csv
    save_file_path = filedialog.asksaveasfilename(
        defaultextension=".csv",  # Default file extension
        filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],  # File type filters
        title=f"All cases processed. Where would you like to save the results?",  # Dialog box title
        initialdir="/media/sf_Summer_Research/CWE_Detection/Results",  # Initial directory
    )

    #Try to save file
    if save_file_path:
        try:
            results_df.to_csv(save_file_path, index=False)
            print(f"Results saved successfully to {save_file_path}")
        except Exception as e:
            print(f"Error saving file: {e}")
    else:
        print("File save operation cancelled.")

    root.destroy()  # Close the root window

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

    results['state_coverage'] = (check_state_coverage(case_statement))
    results['unreachable_states'] = (check_unreachable_states(case_statement))
    results['deadlocks'] = (check_for_deadlocks(case_statement))

    return results

def run_detection_on_file(file_path: str) -> pd.DataFrame:
    """Runs vulnerability detection on the file at the file path

    Args:
        file_path (str): File path of file for detection

    Returns:
        pd.DataFrame: Results of detection on the file
    """
    start_time = time.perf_counter()

    results_df_columns = ['file_name', 'case_number', 'state_coverage', 'unreachable_states', 'deadlocks', 'LoC', 'detection_time']
    results_df = pd.DataFrame(columns=results_df_columns)

    #Load JSON and traverse
    json_data = load_json_file(file_path)
    traverser = AST_Traverser()
    for module in json_data:
        traverser.traverse(module, None)

    # Loop through unsatisfiable conditionals to see if they are now satisfiable
    unsatisfiable_conditionals = copy.deepcopy(traverser.unsatisfiable_conditionals)
    for cond in unsatisfiable_conditionals.values():
        if traverser.determine_conditional_satisfiability(conditional_node=cond):
            traverser.satisfiable_conditionals[cond.node_id] = cond
            traverser.unsatisfiable_conditionals.pop(cond.node_id)
    del unsatisfiable_conditionals

    if len(traverser.case_statements) == 0:
        #If there are no case statements return the one row 
        end_time = time.perf_counter()

        results_df = pd.concat([results_df, pd.DataFrame([{
            'file_name': os.path.basename(file_path),
            'case_number': 'No case statements found',
            'state_coverage': None,
            'unreachable_states': None,
            'deadlocks': None,
            'LoC': traverser.loc,
            'detection_time': (end_time - start_time)
        }])], ignore_index=True)
        return results_df
    else:
        case_num = 1
        #Loop through each case statement and run detection
        for case in traverser.case_statements.values():
            results_row = {
                'file_name': os.path.basename(file_path),
                'case_number': case_num,
                'state_coverage': None,
                'unreachable_states': None,
                'deadlocks': None,
                'LoC': traverser.loc
            }
            detect_CWE_1245(traverser, case, results=results_row)

            end_time = time.perf_counter()
            results_row['detection_time'] = (end_time - start_time)

            #Concat current results and new results row
            results_df = pd.concat([results_df, pd.DataFrame([results_row])], ignore_index=True)
            case_num += 1
    
    return results_df

def run_detection_on_folder(folder_path: str) -> pd.DataFrame:
    """Runs vulnerability detection on each file in the folder at the specified path

    Args:
        folder_path (str): Folder to run detection on

    Returns:
        pd.DataFrame: Dataframe containing the results of detection
    """
    results_df_columns = ['file_name', 'case_number', 'state_coverage', 'unreachable_states', 'deadlocks']
    results_df = pd.DataFrame(columns=results_df_columns)

    #Loop through each file in the folder
    for file in os.listdir(folder_path):
        file_path = os.path.join(folder_path, file)

        results_df = pd.concat([results_df, run_detection_on_file(file_path)], ignore_index=True)
        print(f"\nProcessed file: {file}\n")

    return results_df

def main():
    selected_path = select_files_for_detection()

    #Run folder or file detection based on selected path
    if os.path.isdir(selected_path):
        results_df = run_detection_on_folder(selected_path)
    elif os.path.isfile(selected_path):
        results_df = run_detection_on_file(selected_path)
    else:
        print("Invalid selection. Please select a valid file or folder.")
        return
    
    #Create a row to contain the totals
    total_row = pd.DataFrame([{
        'file_name': 'Total',
        'case_number': results_df['case_number'].count(),
        'state_coverage': {
            'Secure': results_df['state_coverage'].str.startswith('Secure').sum(),
            'Vulnerable': results_df['state_coverage'].str.startswith('Vulnerable').sum(),
            'Inconclusive': results_df['state_coverage'].str.startswith('Inconclusive').sum()
        },
        'unreachable_states': {
            'Secure': results_df['unreachable_states'].str.startswith('Secure').sum(),
            'Vulnerable': results_df['unreachable_states'].str.startswith('Vulnerable').sum(),
            'Inconclusive': results_df['unreachable_states'].str.startswith('Inconclusive').sum()
        },
        'deadlocks': {
            'Secure': results_df['deadlocks'].str.startswith('Secure').sum(),
            'Vulnerable': results_df['deadlocks'].str.startswith('Vulnerable').sum(),
            'Inconclusive': results_df['deadlocks'].str.startswith('Inconclusive').sum()
        },
        'LoC': results_df['LoC'].sum(),
        'detection_time': results_df['detection_time'].sum()
    }])
    results_df = pd.concat([results_df, total_row], ignore_index=True)

    save_results(results_df)

if __name__ == "__main__":
    main()