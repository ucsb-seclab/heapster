import claripy
import sys
import logging

logger = logging.getLogger('WinConditionTracker')
logger.setLevel(logging.ERROR)

def get_fd_all_bytes(fd):
    pos = fd.tell()
    fd.seek(0)
    data, size = fd.read_data(pos)
    return data

def check_input(state, values, fd):
    if values == 'printable':
        ranges = [['!', '~']]
    elif values == 'alphanumeric':
        ranges = [['0', '9'], ['A', 'Z'], ['a', 'z']]
    elif values == 'letters':
        ranges = [['A', 'Z'], ['a', 'z']]
    elif values == 'zero-bytes':
        ranges = [['\0', '\0']]
    elif values == 'ascii':
        ranges = [['\0', '\x7f']]
    elif values == 'any':
        return state
    else:
        logger.error('Invalid input constraint')
        sys.exit(-1)

    # Get all the bytes readed 'til now from this fd.
    sim_file = state.posix.get_fd(fd) 
    stdin = get_fd_all_bytes(sim_file)

    stdin = stdin.chop(8) # Chop every byte!

    constraints = claripy.And()
    for c in stdin:
        constraint = claripy.Or()
        for r in ranges:
            cst_tmp = claripy.And(c >= r[0], c <= r[1])
            constraint = claripy.Or(cst_tmp, constraint)
        constraints = claripy.And(constraint, constraints)
    if state.solver.satisfiable(extra_constraints=[constraints]):
        state.add_constraints(constraints)
        return state
    else:
        logger.error('Constraints over input ({}) are making this vuln state unsat!'.format(values))
        return None

def constrain_input(state, stdin, values):
    if values == 'printable':
        ranges = [['!', '~']]
    elif values == 'alphanumeric':
        ranges = [['0', '9'], ['A', 'Z'], ['a', 'z']]
    elif values == 'letters':
        ranges = [['A', 'Z'], ['a', 'z']]
    elif values == 'zero-bytes':
        ranges = [['\0', '\0']]
    elif values == 'ascii':
        ranges = [['\0', '\x7f']]
    elif values == 'any':
        return state
    else:
        logger.error('Invalid input constraint')
        sys.exit(-1)

    constraints = claripy.And()
    for c in stdin:
        constraint = claripy.Or()
        for r in ranges:
            cst_tmp = claripy.And(c >= r[0], c <= r[1])
            constraint = claripy.Or(cst_tmp, constraint)
        constraints = claripy.And(constraint, constraints)

    if state.solver.satisfiable(extra_constraints=[constraints]):
        state.add_constraints(constraints)
        return state
    else:
        return None
