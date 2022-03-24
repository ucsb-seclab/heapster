
from .soot_statement import SootStmt

class SootBlock(object):

    def __init__(self, label, statements, idx):
        self.label = label
        self.statements = statements
        self.idx = idx

    __slots__ = ['label', 'statements', 'idx']

    def __repr__(self):
        return "<Block %d [%d], %d statements>" % (self.idx if self.idx is not None else -1, self.label, len(self.statements))

    def __str__(self):
        tstr = "//" + repr(self) + "\n"

        for s in self.statements:
            sstr = str(s)
            if not sstr.strip():
                continue
            # assume one line per statement
            tstr += sstr + "\n"
        tstr = tstr.strip()
        return tstr

    @staticmethod
    def from_ir(ir_block, stmt_map=None, idx=None):
        stmts = []
        label = stmt_map[ir_block.getHead()]

        for ir_stmt in ir_block:
            stmt = SootStmt.from_ir(ir_stmt, stmt_map)
            stmts.append(stmt)

        return SootBlock(label, stmts, idx)
