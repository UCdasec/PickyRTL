from node import *
import copy
import re
import itertools

class AST_Traverser():
    def __init__(self):
        self.nodes = {}
        self.variables = {}
        self.outputs = {}
        self.inputs = {}
        self.params = {}
        self.variable_assignments = {} # {variable_name: [assignment1, assignment2, ...]}
        self.case_statements = {}
        self.satisfiable_conditionals = {}
        self.unsatisfiable_conditionals = {}
        self.loc = None
        self.security_sensitive_registers = []

        Node._next_node_id = 0  # Reset the node ID counter

    def check_variables(self, lhs: str, rhs: str):
        """Checks if lhs or rhs have a set value

        Args:
            lhs (str): Left hand side variable to check
            rhs (str): Right hand side variable to check

        Returns:
            (Any | int, Any | int): Returns variable names or associated values
        """
        if lhs in self.variables.keys():
            lhs = self.variables[lhs].value
        if rhs in self.variables.keys():
            rhs = self.variables[rhs].value

        return lhs, rhs
    
    def determine_node_reachability(self, node: Node) -> bool:
        """Determines whether or not the node is reachable. A node is not reachable if it is blocked by an unsatisfiable if statement, elif statement, else clause, or an unreachable case

        Args:
            node (Node): Node to determine if it is reachable

        Returns:
            bool: True if node is reachable, false if not
        """
        if node.reachable is not None and node.reachable:
            return node.reachable

        if node.parent_id is None:
            node.reachable = True
            return True

        parent_node: Node = self.nodes[node.parent_id]
        
        #Check if node is conditionally blocked
        if parent_node.node_type in ['HdlStmIf', 'Elif_Clause', 'Else_Clause']:
            if hasattr(parent_node, 'satisfiable') and parent_node.satisfiable is not None:
                if not self.determine_conditional_satisfiability(parent_node):
                    node.reachable = False
                    return False
                else:
                    node.reachable = True
                    return True
        
        #Check if parent case is satisfiable
        if parent_node.node_type == 'Case':
            if hasattr(parent_node, 'satisfiable') and not parent_node.satisfiable:
                node.reachable = False
                return False
            
        parent_reachable = self.determine_node_reachability(parent_node)
        node.reachable = parent_reachable
        return parent_reachable
    
    def determine_lock_bit_assignment(self, assignment_node: HdlStmAssignNode) -> bool:
        """Determines whether or not the assignment is protected through a lock bit conditional

        Args:
            assignment_node (HdlStmAssignNode): Assignment node to check if it is protected by a lock bit

        Returns:
            bool: True if the assignment is protected by a lock bit
        """
        parent_node = self.nodes[assignment_node.parent_id]
        if isinstance(parent_node, HdlStmIfNode) or isinstance(parent_node, Else_Clause):
            condition = parent_node.condition
            conidtion_variables = self.extract_conditional_variables(condition)
            for var in conidtion_variables:
                if self.variables[var.name].possible_lock_bit_register: #If condition has a lock bit variable
                    destination_node: HdlIdDefNode = self.variables[assignment_node.destination]
                    if not destination_node.security_sensitive:
                        destination_node.security_sensitive = True
                        self.security_sensitive_registers.append(destination_node)
                    return True
                else:
                    return False
        else:
            return False

    def extract_conditional_variables(self, node: dict) -> list[HdlIdDefNode]:
        """Extracts all variables from the condition

        Args:
            node (dict): Condition to extract variables from

        Returns:
            list[HdlIdDefNode]: List of all the variables in the condition
        """
        if node is None:
                return
            
        #When node is a string it is just one variable
        if isinstance(node, str):
                return [self.variables[node]]

            
        node_type = node.get('__class__')

        if node_type == 'HdlOp':
            variables_found = []
            #Extract variables from the ops
            for op in node.get('ops'):
                variables_found.extend(self.extract_conditional_variables(op))
            return variables_found
        elif node_type == 'HdlValueInt':
            return []

    def gather_variable_assignments(self, var: HdlIdDefNode, indirect_destination: str | None=None):
        """_summary_

        Args:
            var (HdlIdDefNode): HdlIdDefNode to gather assignments for
            indirect_destination (str | None, optional): Used if an assignment is an intermediary assignment to another variable. Prevents infinite loops. Defaults to None.

        Returns:
            list[HdlStmAssignNode]: List of indirect and direct assignments to the variable
        """
        if var.direction == 'IN':
            return []
        
        indirect_variable_assignments = []
        direct_variable_assignments = copy.deepcopy(self.variable_assignments[var.name])
        
        for direct_var_assignment in direct_variable_assignments:
            
            #If the variable is assigned to itself or the indirect destination it will cause a circular loop so skip it
            if direct_var_assignment.source == direct_var_assignment.destination or indirect_destination == direct_var_assignment.source:
                continue

            #get variable assignments for the direct assignment source if the source is a variable
            if self.determine_node_reachability(direct_var_assignment):
                if not isinstance(direct_var_assignment.source, int):
                    if direct_var_assignment.source:
                        indirect_variable_assignments.extend(self.gather_variable_assignments(self.variables[direct_var_assignment.source], direct_var_assignment.destination))

        #Convert indirect assignments to direct assignments by copying the assignments and changing the destination
        for indirect_assignment in indirect_variable_assignments.copy():
             new_direct_assignment = copy.deepcopy(indirect_assignment)
             new_direct_assignment.destination = var.name
             direct_variable_assignments.append(new_direct_assignment)

        #Return only reachable assignments
        return [assignment for assignment in direct_variable_assignments if assignment.reachable]
    
    def parse_condition(self, cond: str | dict) -> str:
        """Transforms condition from JSON AST format to python format as a string

        Args:
            cond (str | dict): Condition to parse

        Returns:
            str: Parsed condition in python
        """
        if isinstance(cond, str):
            return cond
        elif isinstance(cond, dict) and cond.get('__class__') == 'HdlOp':
            if cond['fn'] == 'NEG_LOG':
                return f'not {self.parse_condition(cond["ops"][0])}'
            elif cond['fn'] == 'AND_LOG':
                return f'({self.parse_condition(cond["ops"][0])} and {self.parse_condition(cond["ops"][1])})'
            elif cond['fn'] == 'OR_LOG':
                return f'({self.parse_condition(cond["ops"][0])} or {self.parse_condition(cond["ops"][1])})'
            elif cond['fn'] == 'EQ':
                return f'({self.parse_condition(cond["ops"][0])} == {self.parse_condition(cond["ops"][1])})'
            elif cond['fn'] == 'NE':
                return f'({self.parse_condition(cond["ops"][0])} != {self.parse_condition(cond["ops"][1])})'
            elif cond['fn'] == 'LE':
                return f'({self.parse_condition(cond["ops"][0])} <= {self.parse_condition(cond["ops"][1])})'
            elif cond['fn'] == 'GE':
                return f'({self.parse_condition(cond["ops"][0])} >= {self.parse_condition(cond["ops"][1])})'
            elif cond['fn'] == 'LT':
                return f'({self.parse_condition(cond["ops"][0])} < {self.parse_condition(cond["ops"][1])})'
            elif cond['fn'] == 'GT':
                return f'({self.parse_condition(cond["ops"][0])} > {self.parse_condition(cond["ops"][1])})'
            else:
                #Unimplemented conditions that can be implemented later
                return f'UNKNOWN_CONDITION_{cond["fn"]}'
        elif isinstance(cond, dict) and cond.get('__class__') == 'HdlValueInt':
            return cond['val']
        else:
            return 'UNKNOWN_CONDITION'
        
    def get_cond_satisfying_assignments(self, cond: str):
        """Gets all of the variable assignments that satisfy the condition

        Args:
            cond (str): Condition in a python format

        Returns:
            list[dict[str, bool]]: Returns a list of dictionaries. Each dictionary contains a set of variables and their corresponding variables to satisfy the condition
        """
        #Get variables from python condition
        variables = set(re.findall(r'\b[a-zA-Z_][a-zA-Z0-9_]*\b', cond)) - {"and", "or", "not", "(", ")", "==", " ", "!"}
        satisfying_assignments = []
        #Loop through values to determine which values evaluate to True
        for values in itertools.product([False, True], repeat=len(variables)):
            env = dict(zip(variables, values))
            try:
                result = eval(cond, {}, env)
                if result:
                    satisfying_assignments.append(env)
            except Exception as e:
                print(f"Error evaluating conditional expression: {e}")
        return satisfying_assignments

    def determine_conditional_satisfiability(self, conditional_node: HdlStmIfNode | Else_Clause | Elif_Clause):
        """Determines whether the condition in the conditional node can be satisfied by checking all assignments to variables in the condition.

        Args:
            conditional_node (HdlStmIfNode | Else_Clause | Elif_Clause): Conditional node to check if it can be satisfied

        Returns:
            bool: True or False depending on whether the conditional node can be satisfied
        """
        if conditional_node is None:
            return False
        elif conditional_node.satisfiable:
            return True
        else:
            #Assign None to satisfiable to avoid infinitely checking the same if statement
            conditional_node.satisfiable = None

        #Get the variables from the condition
        condition = conditional_node.condition
        conditional_variables = self.extract_conditional_variables(condition)
        
        #Check if all variables are inputs, if so the assignments are out of scope and if statement will be assumed to be satisfiable
        if any(cond_var.direction == 'IN' for cond_var in conditional_variables):
            conditional_node.satisfiable = True
            return True
        
        #If the condition is just a variable with no operators, only need to check if that variable is ever set to true(1)
        if isinstance(condition, str):
            var_assignments = self.gather_variable_assignments(conditional_variables[0])
            #Check to make sure var is assigned 1 at least once
            for var_assignment in var_assignments:
                if var_assignment.source:
                    conditional_node.satisfiable = True
                    return True

        
        #Parse condition
        parsed_condition = self.parse_condition(condition)
        if 'UNKNOWN_CONDITION' in parsed_condition:
            print(f"Unknown condition in conditional node {conditional_node.node_id}: {parsed_condition}, assuming satisfiable")
            conditional_node.satisfiable = True
            return True
        elif any(op in parsed_condition for op in ['==', '!=', '<=', '>', '<', '>=']):
            #TO-DO: Need special handling for equals and !=, but for now assume satisfiable
            conditional_node.satisfiable = True
            return True
        satisfying_assignments = self.get_cond_satisfying_assignments(parsed_condition)   

        if len(satisfying_assignments) == 0:
            conditional_node.satisfiable = False
            return False

        variable_assignments = {}
        #Gather variable assignments to all variables
        for var in conditional_variables:
            variable_assignments[var.name] = [assignment.source for assignment in self.gather_variable_assignments(self.variables[var.name]) if isinstance(assignment.source, int)]

        #Check if any of the conditional satisfying assignments are possible    
        condition_satisfiable = False
        for satisfying_assignment in satisfying_assignments:
            satisfying_assignment_possible = True
            for var, val in satisfying_assignment.items():
                var_assignments = variable_assignments[var]
                if any(bool(val) == bool(assignment) for assignment in var_assignments):
                    continue
                else:
                    satisfying_assignment_possible = False
                    break
            
            if satisfying_assignment_possible:
                condition_satisfiable = True
                break
        if condition_satisfiable:
            conditional_node.satisfiable = True
            return True
        
        #If we can not prove that it is satisfiable then it is unsatisfiable
        conditional_node.satisfiable = False
        return False

    def traverse(self, node: dict, parent_node_id: int | None):
        """Traverses the supplied node

        Args:
            node (dict): The node to traverse
            parent_node_id (int | None): THe id of the parent node

        Returns:
            Any : Returns node, value fo the node, or the callable node traverse method
        """
        if isinstance(node, str):
            return node
        
        if not '__class__' in node:
            return node
        
        if node['__class__'] == 'str':
            return node['val']

        #Get Hdl class and matching traversal method
        node_class = node['__class__']
        traverse_method_name = f"traverse_{node_class}" 
        traverse_method = getattr(self, traverse_method_name, None)

        if callable(traverse_method):
            return traverse_method(node, parent_node_id)
        else:
            print(f"No traverse method defined for {node_class}. Skipping traversal.")

    def traverse_HdlModuleDef(self, node: dict, parent_node_id: int | None):
        """Traverses the declaration and objs of the HdlModuleDef AST node

        Args:
            node (dict): Dictionary containing the hdl module definition
            parent_node_id (int | None): Id of the parent 
        """
        if parent_node_id is not None:
            raise ValueError(f"HdlModuleDef should be the first node, parent_node_id is {parent_node_id}")
        
        self.loc = node['position'][2] - node['position'][0] + 2  # Calculate lines of code from start to end of the module definition

        #Create node
        module_def_node = HdlModuleDefNode()
        self.nodes[module_def_node.node_id] = module_def_node
        
        #Traverse module declaration
        self.traverse(node['dec'], module_def_node.node_id)

        #Traverse module objects
        for obj in node['objs']:
            self.traverse(obj, module_def_node.node_id)

    def traverse_HdlModuleDec(self, node: dict, parent_node_id: int | None):
        """Traverses the ports and parameters of the HdlModuleDec AST node

        Args:
            node (dict): Module declaration node
            parent_node_id (int | None): Id of the parent node
        """
        #Create node
        module_dec_node = HdlModuleDecNode(parent_id=parent_node_id)
        self.nodes[module_dec_node.node_id] = module_dec_node
        self.nodes[parent_node_id].add_child(module_dec_node)

        #traverse the ports and parameters
        for param in node['params']:
            self.traverse(param, module_dec_node.node_id)
        for port in node['ports']:
            self.traverse(port, module_dec_node.node_id)

    def traverse_HdlStmProcess(self, node: dict, parent_node_id: int | None):
        """Traverses the body of the HdlStmProcess AST node

        Args:
            node (dict): Process node to traverse
            parent_node_id (int | None): Id of the parent node
        """
        #Create node
        process_node = HdlStmProcessNode(parent_id=parent_node_id)
        self.nodes[process_node.node_id] = process_node
        self.nodes[parent_node_id].add_child(process_node)

        #Traverse the body
        self.traverse(node['body'], process_node.node_id)

    def traverse_HdlStmBlock(self, node: dict, parent_node_id: int | None):
        """Traverses the body of the HdlStmBlock AST node

        Args:
            node (dict): HdlStmBlock node to traverse
            parent_node_id (int | None): Id of the parent node
        """
        for obj in node['body']:
            self.traverse(obj, parent_node_id)

    def traverse_HdlStmAssign(self, node: dict, parent_node_id: int | None):
        """Traverses the source and destination of the HdlStmAssign AST node. Store the assignment node under the destination variable

        Args:
            node (dict): HdlStmAssign node to traverse
            parent_node_id (int | None): Id of the parent node
        """
        #If the source of the assignment is a ternary operation, traverse the ternary operator
        if isinstance(node['src'], dict) and node['src']['__class__'] == 'HdlOp' and node['src']['fn'] == 'TERNARY':
            destination = self.traverse(node['dst'], None)
            self.traverse_TernaryOp(node=node['src'], parent_node_id=parent_node_id, destination=destination)
            return

        #Create node
        assignment_node = HdlStmAssignNode(source=self.traverse(node['src'], None), destination=self.traverse(node['dst'], None), parent_id=parent_node_id)
        
        if assignment_node.source is None or assignment_node.destination is None:
            print(f"Warning: Assignment source or destination is None in node {assignment_node.node_id}. Discarding the assignment node")
            return

        self.nodes[assignment_node.node_id] = assignment_node
        self.nodes[parent_node_id].add_child(assignment_node)

        #Add assignment to the variable
        self.variable_assignments[assignment_node.destination].append(assignment_node)

        #Determine if assignment is protected by lock bit
        assignment_node.lock_bit_protected = self.determine_lock_bit_assignment(assignment_node=assignment_node)

    def traverse_HdlStmCase(self, node: dict, parent_node_id: int | None):
        """Traverses the HdlStmCase AST node. Stores the case statement switch variable, cases, and default case

        Args:
            node (dict): HdlStmCase node to traverse
            parent_node_id (int | None): Id of the parent node
        """
        #Create case statement node
        if isinstance(node['switch_on'], dict):
            #Handle switch variables that are more than just one variable
            if node['switch_on']['__class__'] == 'HdlOp' and node['switch_on']['fn'] == 'INDEX':
                case_statement_node = HdlStmCaseNode(
                    switch_variable=self.variables[node['switch_on']['ops'][0]],
                    parent_id=parent_node_id,
                    switch_variable_bit_width=self.traverse(node['switch_on']['ops'][1], None)
                )
            else:
                print('Unhandled switch variable for case statement')
                return
        else:
            #One variable switch statements
            case_statement_node = HdlStmCaseNode(switch_variable=self.variables[node['switch_on']], parent_id=parent_node_id)
            
        self.nodes[case_statement_node.node_id] = case_statement_node
        self.nodes[parent_node_id].add_child(case_statement_node)

        self.case_statements[case_statement_node.node_id] = case_statement_node

        #Traverse cases and create nodes for them
        for case in node['cases']:
            case_value = self.traverse(case[0], None)
            
            #Check if case value is a variable with a value, if so add both values to the case values
            if case_value in self.variables.keys() and self.variables[case_value].value is not None:
                case_values = [case_value, self.variables[case_value].value]
            else:
                case_values = [case_value]

            #Create node
            case_node = Case(values=case_values, parent_id=case_statement_node.node_id)
            self.nodes[case_node.node_id] = case_node
            self.nodes[case_statement_node.node_id].add_case(case_node)

            self.traverse(case[1], case_node.node_id)

        #Traverse default if ti exists
        if 'default' in node:
            #Create node
            default_case_node = Case(values=['default'], parent_id=case_statement_node.node_id, satisfiable=True)
            self.nodes[default_case_node.node_id] = default_case_node
            self.nodes[case_statement_node.node_id].add_default(default_case_node)

            self.traverse(node['default'], default_case_node.node_id)

    def traverse_HdlStmIf(self, node: dict, parent_node_id: int | None):
        """Traverses the condition, if_true, elifs, and if_false of the HdlStmIf AST node. Determines if the condition is satisfiable and stores the if statement information

        Args:
            node (dict): HdlStmIf node to traverse
            parent_node_id (int | None): Id of the parent node
        """
        #Create if node
        if_node = HdlStmIfNode(node['cond'], parent_node_id)
        self.nodes[if_node.node_id] = if_node
        self.nodes[parent_node_id].add_child(if_node)

        if self.determine_conditional_satisfiability(if_node):
            self.satisfiable_conditionals[if_node.node_id] = if_node
        else:
            self.unsatisfiable_conditionals[if_node.node_id] = if_node

        self.traverse(node['if_true'], if_node.node_id)

        #Traverse the elifs and create nodes
        for elif_case in node['elifs']:
            elif_node = Elif_Clause(elif_case[0], if_node.node_id)
            self.nodes[elif_node.node_id] = elif_node
            if_node.add_elif(elif_node)
            if_node.add_child(elif_node)

            if self.determine_conditional_satisfiability(elif_node):
                self.satisfiable_conditionals[elif_node.node_id] = elif_node
            else:
                self.unsatisfiable_conditionals[elif_node.node_id] = elif_node

            self.traverse(elif_case[1], elif_node.node_id)
        
        #Create Else clause node for if_false with negative condition of if statement
        if 'if_false' in node:
            cond = {
                '__class__': 'HdlOp',
                'ops': [node['cond']],
                'fn': 'NEG_LOG'
            }
            else_node = Else_Clause(cond, if_node.node_id)
            self.nodes[else_node.node_id] = else_node
            if_node.else_clause = else_node
            if_node.add_child(else_node)

            if self.determine_conditional_satisfiability(else_node):
                self.satisfiable_conditionals[else_node.node_id] = else_node
            else:
                self.unsatisfiable_conditionals[else_node.node_id] = else_node

            self.traverse(node['if_false'], else_node.node_id)

    def traverse_HdlIdDef(self, node: dict, parent_node_id: int | None):
        """Traverses the HdlIdDef AST node. Stores the type, bit_width, value, name, and direction

        Args:
            node (dict): HdlIdDef node to traverse
            parent_node_id (int | None): Id of the parent node
        """
        type_node = node['type']
        variable_bit_width = None
        variable_type = None

        #Get the type of variable and the bit width
        if isinstance(type_node, dict):
            if type_node['__class__'] == 'HdlTypeAuto':
                variable_type = None
                variable_bit_width = 1
            elif type_node['__class__'] == 'HdlOp' and type_node['fn'] == 'PARAMETRIZATION':
                variable_type = type_node['ops'][0]
                variable_bit_width  = self.traverse(type_node['ops'][1], None)
            elif type_node['__class__'] == 'HdlOp' and type_node['fn'] == 'DOUBLE_COLON':
                variable_type = f"{type_node['ops'][0]}::{type_node['ops'][1]}"
            else:
                print('Unknown type for HdlIdDef')
        elif isinstance(type_node, str):
            variable_type = type_node

        #Get the value of the variable if it has one
        value = 0
        if 'value' in node:
            value_node = node['value']
            value = self.traverse(value_node, None)
            if variable_bit_width is None:
                if 'bits' in value_node:
                    variable_bit_width = value_node['bits']
                else:
                    variable_bit_width = None

        #Create node
        id_def_node = HdlIdDefNode(name=node['name']['val'], direction=node['direction'], bit_width=variable_bit_width, type=variable_type, value=value, parent_id=parent_node_id)
        self.nodes[id_def_node.node_id] = id_def_node
        self.nodes[parent_node_id].add_child(id_def_node)

        match id_def_node.direction:
            case "IN":
                self.inputs[id_def_node.name] = id_def_node
            case 'OUT':
                self.outputs[id_def_node.name] = id_def_node
    
        self.variables[id_def_node.name] = id_def_node

        #Initialize variable assignments to an empty list
        self.variable_assignments[id_def_node.name] = []
        
    def traverse_HdlValueInt(self, node: dict, parent_node_id: int | None):
        """Returns the value fo the HdlValueInt AST node

        Args:
            node (dict): HdlValueInt node to traverse
            parent_node_id (int | None): Id of the parent node

        Returns:
            int | None: Value of the HdlValueInt node
        """
        try:
            return int(node['val'], node['base'])
        except ValueError as e:
            print(f"Error converting value '{node['val']}' with base '{node['base']}' to int: {e}")
            return None       

    def traverse_HdlOp(self, node: dict, parent_node_id: int | None):
        """Traverses the left and right side of the HdlOp AST node. Matches the operator function and applies it to the left and right side values

        Args:
            node (dict): HdlOpNode to traverse
            parent_node_id (int | None): Id of the parent node

        Returns:
            Any: Value of the left hand side and right hand side after function is applied
        """
        match node['fn']:
            case 'DOWNTO':
                lhs = self.traverse(node['ops'][0], None)
                rhs = self.traverse(node['ops'][1], None)

                if lhs is None or rhs is None:
                    print(f"Warning: One of the operands in DOWNTO operation is None. lhs: {lhs}, rhs: {rhs}. Returning None")
                    return None

                return lhs - rhs + 1
            case 'ASSIGN':
                #If the source of the assignment is a ternary operator, treat it like if statements
                if isinstance(node['ops'][1], dict) and node['ops'][1]['__class__'] == 'HdlOp' and node['ops'][1]['fn'] == 'TERNARY':
                    self.traverse_TernaryOp(node=node['ops'][1], parent_node_id=parent_node_id, destination=node['ops'][0])
                    return

                source = self.traverse(node['ops'][1], None)
                destination = self.traverse(node['ops'][0], None)
                assignment_node = HdlStmAssignNode(source=source, destination=destination, parent_id=parent_node_id)

                self.nodes[assignment_node.node_id] = assignment_node
                self.nodes[parent_node_id].add_child(assignment_node)

                self.variable_assignments[assignment_node.destination].append(assignment_node)

                assignment_node.lock_bit_protected = self.determine_lock_bit_assignment(assignment_node=assignment_node)
            case 'INDEX':
                #TO-DO: FIgure out something with the index. This is a stop gap
                #Returns the variable name, but does not handle the actual indexing
                return node['ops'][0]
            case 'SUB':
                lhs = self.traverse(node['ops'][0], None)
                rhs = self.traverse(node['ops'][1], None)

                lhs, rhs = self.check_variables(lhs, rhs)

                if lhs is None or rhs is None:
                    print(f"Warning: One of the operands in SUB operation is None. lhs: {lhs}, rhs: {rhs}. Returning None")
                    return None

                return lhs - rhs
            case 'MUL':
                lhs = self.traverse(node['ops'][0], None)
                rhs = self.traverse(node['ops'][1], None)

                lhs, rhs = self.check_variables(lhs, rhs)

                if lhs is None or rhs is None:
                    print(f"Warning: One of the operands in MUL operation is None. lhs: {lhs}, rhs: {rhs}. Returning None")
                    return None

                return lhs * rhs
            case 'ADD':
                lhs = self.traverse(node['ops'][0], None)
                rhs = self.traverse(node['ops'][1], None)

                lhs, rhs = self.check_variables(lhs, rhs)

                if lhs is None or rhs is None:
                    print(f"Warning: One of the operands in ADD operation is None. lhs: {lhs}, rhs: {rhs}. Returning None")
                    return None

                return lhs + rhs
            case 'MAP_ASSOCIATION':
                #Maps variables to singed or unsigned. I have no need to handle this right now
                pass
            case _:
                print(f"HdlOP not implemented for {node['fn']}")
    
    def traverse_TernaryOp(self, node: dict, parent_node_id: int | None, destination: str):
        """Traverses the ternary operator and converts the ternary condition to an HdlStmIfNode for storage. 

        Args:
            node (dict): _description_
            parent_node_id (int | None): _description_
            destination (str): Name of the destination variable

        Returns:
            HdlStmIfNode: Ternary operator formatted as HdlStmIIfNode
        """
        #Create if statement node for ternary operator
        if_node = HdlStmIfNode(condition=node['ops'][0], parent_id=parent_node_id)
        self.nodes[if_node.node_id] = if_node
        self.nodes[parent_node_id].add_child(if_node)

        #Determine if the condition is satisfiable
        if self.determine_conditional_satisfiability(if_node):
            self.satisfiable_conditionals[if_node.node_id] = if_node
        else:
            self.unsatisfiable_conditionals[if_node.node_id] = if_node

        #If there is another ternary operation, traverse it
        if isinstance(node['ops'][1], dict) and node['ops'][1]['__class__'] == 'HdlOp' and node['ops'][1]['fn'] == 'TERNARY':
            if_true_node = self.traverse_TernaryOp(node['ops'][1], parent_node_id=if_node.node_id, destination=destination)
            self.nodes[if_node.node_id].add_child(if_true_node)
        else:
            #Create an assignment node to the original destination
            source = self.traverse(node['ops'][1], if_node.node_id)
            assignment_node = HdlStmAssignNode(source=source, destination=destination, parent_id=if_node.node_id)
            self.nodes[assignment_node.node_id] = assignment_node
            self.nodes[if_node.node_id].add_child(assignment_node)

            self.variable_assignments[assignment_node.destination].append(assignment_node)

            assignment_node.lock_bit_protected = self.determine_lock_bit_assignment(assignment_node=assignment_node)

        #Convert second half of ternary operation to else clause with negative of original condition
        else_cond = {
                '__class__': 'HdlOp',
                'ops': [if_node.condition],
                'fn': 'NEG_LOG'
        }

        else_clause = Else_Clause(else_cond, parent_id=if_node.node_id)
        self.nodes[else_clause.node_id] = else_clause
        if_node.else_clause = else_clause
        if_node.add_child(else_clause)

        #Determine if the condition is satisfiable
        if self.determine_conditional_satisfiability(else_clause):
            self.satisfiable_conditionals[else_clause.node_id] = else_clause
        else:
            self.unsatisfiable_conditionals[else_clause.node_id] = else_clause

        #If there is another ternary operation, traverse it
        if isinstance(node['ops'][2], dict) and node['ops'][2]['__class__'] == 'HdlOp' and node['ops'][2]['fn'] == 'TERNARY':
            if_false_node = self.traverse_TernaryOp(node['ops'][2], parent_node_id=else_clause.node_id, destination=destination)
            self.nodes[else_clause.node_id].add_child(if_false_node)
        else:
            #Create an assignment node to the original destination
            source = self.traverse(node['ops'][2], else_clause.node_id)
            assignment_node = HdlStmAssignNode(source=source, destination=destination, parent_id=else_clause.node_id)
            self.nodes[assignment_node.node_id] = assignment_node
            self.nodes[else_clause.node_id].add_child(assignment_node)

            self.variable_assignments[assignment_node.destination].append(assignment_node)

            assignment_node.lock_bit_protected = self.determine_lock_bit_assignment(assignment_node=assignment_node)
        return if_node

    def traverse_HdlCompInst(self, node: dict, parent_node_id: int | None):
        """Traverses param_map and port_map of HdlCompInst AST node and sets the module_mapped property of those variables

        Args:
            node (dict): HdlCompInst node to traverse
            parent_node_id (int | None): Id of parent node
        """
        for mapping in node['param_map']:
            if isinstance(mapping, str):
                param_name = mapping
            elif mapping['__class__'] == 'HdlOp' and mapping['fn'] == 'MAP_ASSOCIATION':
                param_name = mapping['ops'][1]
            else:
                print(f"Unimplemented param mapping: {mapping['__class__']} in HdlCompInst")
                return
            
            if not isinstance(param_name, str):
                continue
            param: HdlIdDefNode = self.variables[param_name]
            param.module_mapping = node['module_name']

        for mapping in node['port_map']:
            if isinstance(mapping, str):
                port_name = mapping
            elif mapping['__class__'] == 'HdlOp' and mapping['fn'] == 'MAP_ASSOCIATION':
                port_name = mapping['ops'][1]
            else:
                continue
            
            if not isinstance(port_name, str):
                continue
            port: HdlIdDefNode = self.variables[port_name]
            port.module_mapping = node['module_name']
