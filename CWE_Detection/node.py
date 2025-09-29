import math
import re
class Node():
    _next_node_id = -1
    def __init__(self, node_type, start_line, end_line, parent_id=None):
        self.node_type = node_type 
        self.node_id = Node._next_node_id
        Node._next_node_id += 1
        self.parent_id = parent_id
        self.children = {}
        self.reachable = None #Determines whether a node is reachable or blocked through unsatisfiable if statements or unreachable case statements
        self.start_line = start_line
        self.end_line = end_line 

    def add_child(self, child_node):
        """Adds child_node to self.children

        Args:
            child_node (Node): Node that will be added as a child node
        """
        self.children[child_node.node_id] = child_node


class HdlModuleDefNode(Node):
    def __init__(self, start_line, end_line):
        super().__init__('HdlModuleDef', start_line, end_line)

class HdlModuleDecNode(Node):
    def __init__(self, parent_id, start_line, end_line):
        super().__init__('HdlModuleDec', start_line, end_line, parent_id)

class HdlStmProcessNode(Node):
    def __init__(self, parent_id, start_line, end_line):
        super().__init__("HdlStmProcess", start_line, end_line, parent_id)

class HdlIdDefNode(Node):
    def __init__(self, name, direction, bit_width, type, value, parent_id, start_line, end_line):
        super().__init__('HdlIdDef', start_line, end_line, parent_id)
        self.name = name
        self.direction = direction
        self.bit_width = bit_width
        self.variable_type = type
        self.value = value
        self.module_mapping = None
        self.possible_lock_bit_register = self.is_lock_name() if direction == "IN" else False
        self.security_sensitive = False
        self.debug_register = self.is_debug_register() if direction == "IN" else False


    def calculate_possible_values(self):
        """Calculates the bit width of the variable

        Returns:
            float | None: Returns bit width of the variable
        """
        if self.bit_width is None:
            return 1 #TO-DO see if there is something I can do better here
        return math.pow(2, self.bit_width)
    
    def is_lock_name(self) -> bool:
        """Determines if the variable is a lock bit register

        Returns:
            bool: True if the variable is a lock bit register, False otherwise
        """
        LOCK_NAME_PATTERNS = [r"(?<!b)lock", r"lck", r"(?<!c)lk(?!c)"] #Detects block currently
        return any(re.search(p, self.name.lower()) for p in LOCK_NAME_PATTERNS)

    def is_debug_register(self) -> bool:
        """Determines if the variable is a debug register

        Returns:
            bool: True if the variable is a debug register, False otherwise
        """
        DEBUG_NAME_PATTERNS = [r"debug"]
        return any(re.search(p, self.name.lower()) for p in DEBUG_NAME_PATTERNS)
class HdlStmAssignNode(Node):
    def __init__(self, source, destination, parent_id, start_line, end_line):
        super().__init__('HdlStmAssign', start_line, end_line, parent_id)
        self.source = source
        self.destination = destination
        if self.source == 0:
            self.zeroized = True
        else:
            self.zeroized = False
        self.lock_bit_protected = False
        self.isDebugAssignment = False


class HdlStmCaseNode(Node):
    def __init__(self, switch_variable, parent_id, start_line, end_line, switch_variable_bit_width=None):
        super().__init__('HdlStmCase', start_line, end_line, parent_id)
        del self.children #The children of the case statement are the cases
        self.switch_variable = switch_variable
        self.switch_variable_bit_width = switch_variable_bit_width
        self.cases = {}
        self.default = None
        self.possible_case_values = []
        self.case_primary_values = []

    def add_case(self, case_node):
        """Adds case_node to self.cases

        Args:
            case_node (Case): Case node to add
        """
        self.cases[case_node.node_id] = case_node
        for case_value in case_node.case_values:
            self.possible_case_values.append(case_value)
        self.case_primary_values.append(case_node.primary_value)

    def add_default(self, default_node):
        """Adds default case node to self.default

        Args:
            default_node (Case): Default case to add
        """
        self.default = default_node
        self.possible_case_values.append(default_node.primary_value)
        self.case_primary_values.append(default_node.primary_value)

    def calculate_possible_values(self):
        """Calculates number of possible values for switch variable

        Returns:
            float: Number of possible values for switch variable
        """
        return math.pow(2, self.switch_variable_bit_width)

class Case(Node):
    def __init__(self, values, parent_id, start_line, end_line, satisfiable=False):
        super().__init__('Case', start_line, end_line, parent_id)
        self.case_values = values
        self.satisfiable = satisfiable
        self.primary_value = values[0]

class HdlStmIfNode(Node):
    def __init__(self, condition, parent_id, start_line, end_line):
        super().__init__('HdlStmIf', start_line, end_line, parent_id)
        self.condition = condition
        self.satisfiable = False
        self.elifs = []
        self.else_clause = None

    def add_elif(self, elif_node):
        """Adds elif node to self.elifs

        Args:
            elif_node (Elif_Clause): Elif clause to add
        """
        self.elifs.append(elif_node)

class Elif_Clause(Node):
    def __init__(self, condition, parent_id, start_line, end_line):
        super().__init__('Elif_Clause', start_line, end_line, parent_id)
        self.condition = condition
        self.satisfiable = False

class Else_Clause(Node):
    def __init__(self, condition, parent_id, start_line, end_line):
        super().__init__('Else_Clause', start_line, end_line, parent_id)
        self.condition = condition
        self.satisfiable = False