
import logging 

from angr.exploration_techniques import ExplorationTechnique
from angr import SimProcedure

l = logging.getLogger("SkipSVC")
l.setLevel(logging.CRITICAL)

svc_skipped_cnt = 0 

def hook_svc(state):
    global svc_skipped_cnt

    l.info("Skipping SVC")
    sym_var_name = "svc_{}_{}_ret_value".format(hex(state.addr), svc_skipped_cnt)
    #state.state_dirty_things.svc_returns.append(sym_var_name)
    #state.state_dirty_things.svc_skipped_cnt+=1
    svc_skipped_cnt+=1
    setattr(state.regs, "pc", state.regs.pc + 0x2) # skip the SVC
    setattr(state.regs, "r0", state.solver.BVS(sym_var_name, 4*8)) # set symbolic return value.
    state.globals["svc_found"] = True
    
    # Sanity check, we don't expect SVCs during the tracing with HeapHopper.
    # NOTE: heap implementations do not use it in our dataset.
    # FIXME: this is not supported by angr.
    assert(False)

class SkipSVC(ExplorationTechnique):

    def __init__(self):
        super(SkipSVC, self).__init__()

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