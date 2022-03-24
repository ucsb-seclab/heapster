
from angr.exploration_techniques import ExplorationTechnique
from angr import SimProcedure
from ..utils import *


def hook_svc(state):
    l.info("Skipping SVC")
    sym_var_name = "svc_{}_{}_ret_value".format(hex(state.addr), state.state_dirty_things.svc_skipped_cnt)
    state.state_dirty_things.svc_returns.append(sym_var_name)
    state.state_dirty_things.svc_skipped_cnt+=1
    setattr(state.regs, "pc", state.regs.pc + 0x2) # skip the SVC
    setattr(state.regs, "r0", state.solver.BVS(sym_var_name, 4*8)) # set symbolic return value.

class SkipSVC(ExplorationTechnique):

    def __init__(self, heap_attack):
        super(SkipSVC, self).__init__()
        self.heap_attack = heap_attack

    def setup(self, simgr):
        return True

    def step_state(self, simgr, state, **kwargs):
        try:
            state_block = state.block()
        except Exception as e:
            return simgr.step_state(state, **kwargs)
        if state_block.vex.jumpkind == "Ijk_Sys_syscall":
            state.project.hook(state_block.instruction_addrs[-1], hook_svc)
        return simgr.step_state(state, **kwargs)