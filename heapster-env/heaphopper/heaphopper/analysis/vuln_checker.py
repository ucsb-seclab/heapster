import angr
import logging
from ..utils.input import check_input

logger = logging.getLogger('VulnChecker')


class VulnChecker(angr.exploration_techniques.ExplorationTechnique):
    def __init__(self, fd, pre_constraint, stdin_values, stop_found, filter_fake_free):
        super(VulnChecker, self).__init__()
        self.pre_constraint = pre_constraint
        self.stdin_values = stdin_values
        self.fd = fd
        self.stop_found = stop_found
        self.filter_fake_free = filter_fake_free

    def step(self, sm, stash, **kwargs):
        # We stop if we find the first vuln
        
        #print("---In VulnChecker---")
        #print(sm.active)
        sm.move(from_stash='active', to_stash='vuln', filter_func=lambda p: p.heaphopper.vulnerable)
        #print(sm.vuln)
        #print("---------------------")

        # For assertions with hangs
        sm.move(from_stash='active', to_stash='hangs', filter_func=lambda p: p.heaphopper.hangs)
        # For faulty states (e.g., malloc failed)
        sm.move(from_stash='active', to_stash='faulty', filter_func=lambda p: p.heaphopper.faulty)
        
        # If there are no pre-constraints over the input and the sm
        # hasvulnerable states
        if not self.pre_constraint and len(sm.vuln):
            # Move vulnerable state in unsat if the input values cannot reach this state
            sm.move(from_stash='vuln', to_stash='unsat_input',
                    filter_func=lambda p: check_input(p, self.stdin_values, self.fd) is None)
            
            # If we have moved all the vuln states to unsat it's sad...  
            if not len(sm.vuln):
                logger.info('Vuln path not reachable through stdin constraints')

        if self.stop_found and len(sm.vuln):
            print("Moving {} deferred to unused stash because we have a vuln".format(len(sm.deferred)))
            sm.move(from_stash='deferred', to_stash='unused')
            
        elif self.filter_fake_free and len(sm.vuln):
            if any(p.heaphopper.fake_frees for p in sm.vuln):
                sm.move(from_stash='deferred', to_stash='unused')

        return sm.step(stash=stash)
