from node import HdlStmIfNode, Else_Clause, Elif_Clause

class FSM():
    def __init__(self, state_variable):
        self.state_variable = state_variable
        self.states = set()
        self.transitions = set()

    def unreachable_states(self):
        """Returns a set of unreachable states in the FSM

        Returns:
            set: Unreachable states in the FSM
        """
        reachable_states = set()
        for transition in self.transitions:
            if transition.reachable:
                reachable_states.add(transition.start_state)
                reachable_states.add(transition.next_state)
        return self.states - reachable_states
    
    def deadlock_states(self):
        """Returns a set of deadlock states in the FSM

        Returns:
            set: Deadlock states in the FSM
        """
        deadlock_states = set()
        for state in self.states:
            has_outgoing_transition = False
            for transition in self.transitions:
                if transition.start_state == state and transition.reachable and transition.next_state != state:
                    has_outgoing_transition = True
                    break
            if not has_outgoing_transition:
                deadlock_states.add(state)
        return deadlock_states

class Transition:
    def __init__(self, start_state, next_state, assignment, condition: HdlStmIfNode | Elif_Clause | Else_Clause | None):
        self.start_state = start_state
        self.next_state = next_state
        self.assignment = assignment
        self.condition: HdlStmIfNode | Elif_Clause | Else_Clause | None = condition
        if (self.condition is None) or (self.condition.reachable and self.condition.satisfiable):
            self.reachable = True
        else:
            self.reachable = False
        