
from angr.exploration_techniques import ExplorationTechnique
import logging
l = logging.getLogger("TheDeadendinator")


class TheDeadendinator(ExplorationTechnique):
    """
    Do you need all those deadended states eating up your ram? No? They're deadended right? Not useful!

    You need The Deadendinator!

    It gets rid of your deadended paths. That's it.

    simgr.use_technique(TheDeadendinator())

    Done!
    """

    def __init__(self, deadended_stash='deadended'):
        super(TheDeadendinator, self).__init__()
        self.deadend_stash = deadended_stash

    def step(self, simgr, stash, **kwargs):
        simgr = simgr.step(stash=stash, **kwargs)
        if len(simgr.stashes[self.deadend_stash]) > 0:
            l.debug("Obliterating %d dead-end states!" % len(simgr.stashes[self.deadend_stash]))
            while len(simgr.stashes[self.deadend_stash]) > 0:
                s = simgr.stashes[self.deadend_stash].pop()
                del s
        return simgr
