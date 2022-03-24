
from . import convert_soot_attributes


class SootMethod(object):

    __slots__ = ['class_name', 'name', 'ret', 'attrs', 'attrs', 'exceptions', 'blocks', 'params', 'block_by_label', 'basic_cfg', 'exceptional_preds']

    def __init__(self, class_name, name, params, ret, attrs, exceptions, blocks, basic_cfg, exceptional_preds):
        self.class_name = class_name
        self.name = name
        self.params = params
        self.ret = ret
        self.attrs = attrs
        self.exceptions = exceptions
        self.blocks = blocks
        self.basic_cfg = basic_cfg
        self.exceptional_preds = exceptional_preds

        self.block_by_label = dict((block.label, block) for block in self.blocks)

    def __str__(self):
        tstr = "//" + repr(self) + "\n"
        if self.attrs:
            tstr += " ".join([a.lower() for a in self.attrs]) + " "
        tstr += "%s %s(%s){\n" % (self.ret, self.name, ", ".join(self.params))

        for idx, b in enumerate(self.blocks):
            tstr += "\n".join(["\t"+line for line in str(b).split("\n")]) + "\n"

        tstr += "}\n"
        return tstr

    @staticmethod
    def from_ir(class_name, ir_method):
        blocks = []
        from collections import defaultdict
        basic_cfg = defaultdict(list)
        exceptional_preds = defaultdict(list)

        if ir_method.hasActiveBody():
            body = ir_method.getActiveBody()
            from soot.toolkits.graph import ExceptionalBlockGraph
            cfg = ExceptionalBlockGraph(body)
            units = body.getUnits()

            # this should work, I assume that since here we are in Jython the map is "hashed" 
            # based on object identity (and not value), equivalent of Java == operator or Python is operator
            # we create a map to assign to every instruction instance a label
            stmt_map = {u: i for i, u in enumerate(units)}
            # We need index and block maps to consistently retrieve soot_blocks later when we create
            # links to successors
            idx_map = {ir_block: idx for idx, ir_block in enumerate(cfg)}
            block_map = dict()
            for ir_block in cfg:
                soot_block = SootBlock.from_ir(ir_block, stmt_map, idx_map[ir_block])
                blocks.append(soot_block)
                block_map[idx_map[ir_block]] = soot_block

            # Walk through the CFG again to link soot_blocks to the successors soot_blocks
            for ir_block in cfg:
                idx = idx_map[ir_block]
                soot_block = block_map[idx]
                succs = ir_block.getSuccs()
                for succ in succs:
                    succ_idx = idx_map[succ]
                    succ_soot_block = block_map[succ_idx]
                    basic_cfg[soot_block].append(succ_soot_block)

            # Walk through the CFG again to link exceptional predecessors: soot_blocks
            # that are predecessors of a given block when only exceptional control flow is considered.
            for ir_block in cfg:
                idx = idx_map[ir_block]
                soot_block = block_map[idx]
                preds = cfg.getExceptionalPredsOf(ir_block)
                for pred in preds:
                    pred_idx = idx_map[pred]
                    pred_soot_block = block_map[pred_idx]
                    exceptional_preds[soot_block].append(pred_soot_block)

            from .soot_value import SootValue
            stmt_to_block_idx = {}
            for ir_block in cfg:
                for ir_stmt in ir_block:
                    stmt_to_block_idx[ir_stmt] = idx_map[ir_block]

            for ir_block in cfg:
                for ir_stmt in ir_block:
                    if 'Assign' in ir_stmt.getClass().getSimpleName():
                        ir_expr = ir_stmt.getRightOp()
                        if 'Phi' in ir_expr.getClass().getSimpleName():
                            values = [(SootValue.from_ir(v.getValue()), stmt_to_block_idx[v.getUnit()]) for v in ir_expr.getArgs()]

                            phi_expr = SootValue.IREXPR_TO_EXPR[ir_expr]
                            phi_expr.values = values


            # "Free" map
            SootValue.IREXPR_TO_EXPR = {}

        params = tuple(str(p) for p in ir_method.getParameterTypes())
        attrs = convert_soot_attributes(ir_method.getModifiers())
        exceptions = tuple(e.getName() for e in ir_method.getExceptions())
        rt = str(ir_method.getReturnType())

        return SootMethod(class_name, ir_method.getName(), params, rt, attrs, exceptions, blocks, basic_cfg, exceptional_preds)


from .soot_block import SootBlock
