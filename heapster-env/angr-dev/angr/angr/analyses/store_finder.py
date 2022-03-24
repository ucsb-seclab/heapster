
from collections import defaultdict

from cle.loader import MetaELF
from cle.backends import Section, Segment
import pyvex
import claripy

from ..engines.light import SimEngineLight, SimEngineLightVEXMixin
from . import register_analysis
from .analysis import Analysis
from .forward_analysis import FunctionGraphVisitor, SingleNodeGraphVisitor, ForwardAnalysis
from .propagator.vex_vars import VEXTmp

import logging
l = logging.getLogger("StoreFinder")
l.setLevel(logging.DEBUG)


class SimEngineStoreFinderVEX(
    SimEngineLightVEXMixin,
    SimEngineLight,
):
    def __init__(self, project):
        super().__init__()
        self.project = project
        self.stores = []

    #
    # Utils
    #

    def _is_addr_uninitialized(self, addr):
        # is it writing to a global, uninitialized region?
        obj = self.project.loader.find_object_containing(addr)
        if obj is not None:
            if not obj.has_memory:
                # Objects without memory are definitely uninitialized
                return True
            section = obj.find_section_containing(addr)  # type: Section
            if section is not None:
                return section.name in {'.bss', }

            if isinstance(obj, MetaELF):
                # for ELFs, if p_memsz >= p_filesz, the extra bytes are considered NOBITS
                # https://docs.oracle.com/cd/E19120-01/open.solaris/819-0690/gjpww/index.html
                segment = obj.find_segment_containing(addr)  # type: Segment
                if segment is not None and segment.memsize > segment.filesize:
                    return segment.vaddr + segment.filesize <= addr < segment.vaddr + segment.memsize
        return False

    def _is_pointer(self, addr):
        if isinstance(addr, int):
            if addr > 0x400:
                return self.project.loader.find_object_containing(addr) is not None
        return False

    #
    # Statement handlers
    #

    def _handle_function(self, *args, **kwargs):
        pass

    def _handle_WrTmp(self, stmt):
        super()._handle_WrTmp(stmt)
        return

    def _handle_Put(self, stmt):
        return

    def _handle_Store(self, stmt):
        blockloc = self._codeloc(block_only=True)
        import ipdb; ipdb.set_trace()

    def _handle_StoreG(self, stmt):
        blockloc = self._codeloc(block_only=True)
        import ipdb; ipdb.set_trace()

    #
    # Expression handlers
    #
    def _handle_Get(self, expr):
        return None

    def _handle_Load(self, expr):
        return 

    def _debug_Load(self, expr):
        return

    def _handle_LoadG(self, stmt):
        return

    def _handle_RdTmp(self, expr):
        return


class StoreFinder(ForwardAnalysis, Analysis):  # pylint:disable=abstract-method
    """
    Finds possible initializations for global data sections and generate an overlay to be used in other analyses later
    on.
    """

    def __init__(self, func=None, max_iterations=1):
        if func is not None:
            graph_visitor = FunctionGraphVisitor(func, func_graph)
        else:
            raise ValueError('Unsupported analysis target.')

        ForwardAnalysis.__init__(self, order_jobs=True, allow_merging=True, allow_widening=False,
                                 graph_visitor=graph_visitor)

        self._function = func
        self._engine_vex = SimEngineStoreFinderVEX(self.project)
        self._engine_ail = None
        self._stores = []

        self._analyze()

    #
    # Main analysis routines
    #

    def _pre_analysis(self):
        pass

    def _pre_job_handling(self, job):
        pass

    def _initial_abstract_state(self, node):
        return None

    def _merge_states(self, node, *states):
        return None

    def _run_on_node(self, node, state):

        block = self.project.factory.block(node.addr, node.size, opt_level=1, cross_insn_opt=False)
        block_key = node.addr
        engine = self._engine_vex

        engine.process(None, block=block, fail_fast=self._fail_fast)

        self._node_iterations[block_key] += 1

        if self._node_iterations[block_key] < self._max_iterations:
            return True, None
        else:
            return False, None

    def _intra_analysis(self):
        pass

    def _post_analysis(self):
        pass


register_analysis(StoreFinder, "StoreFinder")
register_analysis(StoreFinder, "StoreFinder")
