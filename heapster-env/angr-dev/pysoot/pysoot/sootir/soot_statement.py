
from .soot_value import SootValue


class SootStmt(object):

    NAME_TO_CLASS = {}

    def __init__(self, label, offset):
        self.label = label
        self.offset = offset

    __slots__ = ['label', 'offset']

    @staticmethod
    def from_ir(ir_stmt, stmt_map=None):
        stmt_type = ir_stmt.getClass().getSimpleName()
        stmt_class = SootStmt.NAME_TO_CLASS.get(stmt_type, None)

        if stmt_class is None:
            raise NotImplementedError("Statement type %s is not supported yet." % stmt_type)

        # TODO it seems that soot always set bytecode offset to null
        return stmt_class.from_ir(stmt_map[ir_stmt], 0, ir_stmt, stmt_map)


class DefinitionStmt(SootStmt):
    def __init__(self, label, offset, left_op, right_op):
        super(DefinitionStmt, self).__init__(label, offset)
        self.left_op = left_op
        self.right_op = right_op

    __slots__ = ['left_op', 'right_op']

    def __str__(self):
        return "%s = %s" % (str(self.left_op), str(self.right_op))

    @staticmethod
    def from_ir(label, offset, ir_stmt, stmt_map=None):
        raise NotImplementedError()


class AssignStmt(DefinitionStmt):
    def __init__(self, label, offset, left_op, right_op):
        super(AssignStmt, self).__init__(label, offset, left_op, right_op)

    __slots__ = []

    def __str__(self):
        return "%s = %s" % (str(self.left_op), str(self.right_op))

    @staticmethod
    def from_ir(label, offset, ir_stmt, stmt_map=None):
        return AssignStmt(label, offset, SootValue.from_ir(ir_stmt.getLeftOp()), SootValue.from_ir(ir_stmt.getRightOp()))


class IdentityStmt(DefinitionStmt):
    def __init__(self, label, offset, left_op, right_op):
        super(IdentityStmt, self).__init__(label, offset, left_op, right_op)

    __slots__ = []

    def __str__(self):
        return "%s <- %s" % (str(self.left_op), str(self.right_op))

    @staticmethod
    def from_ir(label, offset, ir_stmt, stmt_map=None):
        return IdentityStmt(label, offset, SootValue.from_ir(ir_stmt.getLeftOp()), SootValue.from_ir(ir_stmt.getRightOp()))


class BreakpointStmt(SootStmt):
    def __init__(self, label, offset):
        super(BreakpointStmt, self).__init__(label, offset)

    __slots__ = []

    def __str__(self):
        return "SootBreakpoint"

    @staticmethod
    def from_ir(label, offset, ir_stmt, stmt_map=None):
        return BreakpointStmt(label, offset)


class EnterMonitorStmt(SootStmt):
    def __init__(self, label, offset, obj):
        super(EnterMonitorStmt, self).__init__(label, offset)
        self.obj = obj

    __slots__ = ['obj']

    def __str__(self):
        return "EnterMonitor(%s)" % str(self.obj)

    @staticmethod
    def from_ir(label, offset, ir_stmt, stmt_map=None):
        return EnterMonitorStmt(label, offset, SootValue.from_ir(ir_stmt.getOp()))


class ExitMonitorStmt(SootStmt):
    def __init__(self, label, offset, obj):
        super(ExitMonitorStmt, self).__init__(label, offset)
        self.obj = obj

    __slots__ = ['obj']

    def __str__(self):
        return "ExitMonitor(%s)" % str(self.obj)

    @staticmethod
    def from_ir(label, offset, ir_stmt, stmt_map=None):
        return ExitMonitorStmt(label, offset, SootValue.from_ir(ir_stmt.getOp()))


class GotoStmt(SootStmt):
    def __init__(self, label, offset, target):
        super(GotoStmt, self).__init__(label, offset)
        self.target = target

    __slots__ = ['target']

    def __str__(self):
        return "goto %d" % self.target

    @staticmethod
    def from_ir(label, offset, ir_stmt, stmt_map=None):
        return GotoStmt(label, offset, stmt_map[ir_stmt.getTarget()])


class IfStmt(SootStmt):
    def __init__(self, label, offset, condition, target):
        super(IfStmt, self).__init__(label, offset)
        self.condition = condition
        self.target = target

    __slots__ = ['condition', 'target']

    def __str__(self):
        return "if(%s) goto %s" % (str(self.condition), str(self.target))

    @staticmethod
    def from_ir(label, offset, ir_stmt, stmt_map=None):
        return IfStmt(label, offset, SootValue.from_ir(ir_stmt.getCondition()),
                      stmt_map[ir_stmt.getTarget()])


class InvokeStmt(SootStmt):
    def __init__(self, label, offset, invoke_expr):
        super(InvokeStmt, self).__init__(label, offset)
        self.invoke_expr = invoke_expr

    __slots__ = ['invoke_expr']

    def __str__(self):
        return str(self.invoke_expr)

    @staticmethod
    def from_ir(label, offset, ir_stmt, stmt_map=None):
        return InvokeStmt(label, offset, SootValue.from_ir(ir_stmt.getInvokeExpr()))


class ReturnStmt(SootStmt):
    def __init__(self, label, offset, value):
        super(ReturnStmt, self).__init__(label, offset)
        self.value = value

    __slots__ = ['value']

    def __str__(self):
        return "return %s" % str(self.value)

    @staticmethod
    def from_ir(label, offset, ir_stmt, stmt_map=None):
        return ReturnStmt(label, offset, SootValue.from_ir(ir_stmt.getOp()))


class ReturnVoidStmt(SootStmt):
    def __init__(self, label, offset):
        super(ReturnVoidStmt, self).__init__(label, offset)

    __slots__ = []

    def __str__(self):
        return "return null"

    @staticmethod
    def from_ir(label, offset, ir_stmt, stmt_map=None):
        return ReturnVoidStmt(label, offset)


class LookupSwitchStmt(SootStmt):
    def __init__(self, label, offset, key, lookup_values_and_targets, default_target):
        super(LookupSwitchStmt, self).__init__(label, offset)
        self.key = key
        self.lookup_values_and_targets = lookup_values_and_targets
        self.default_target = default_target

    __slots__ = ['key', 'lookup_values_and_targets', 'default_target']

    def __str__(self):
        return "switch_table(%s) %s default: %s" % (str(self.key),
                                              repr(self.lookup_values_and_targets),
                                              str(self.default_target)
                                              )

    @staticmethod
    def from_ir(label, offset, ir_stmt, stmt_map=None):
        lookup_values = [int(str(v)) for v in ir_stmt.getLookupValues()]
        targets = [stmt_map[t] for t in ir_stmt.getTargets()]
        lookup_values_and_targets = {k: v for k, v in zip(lookup_values, targets)}

        return LookupSwitchStmt(label, offset, SootValue.from_ir(ir_stmt.getKey()), lookup_values_and_targets,
                                stmt_map[ir_stmt.getDefaultTarget()])


class TableSwitchStmt(SootStmt):
    def __init__(self, label, offset, key, low_index, high_index, targets, default_target, lookup_values_and_targets):
        super(TableSwitchStmt, self).__init__(label, offset)
        self.key = key
        self.low_index = low_index
        self.high_index = high_index
        self.targets = targets
        self.lookup_values_and_targets = lookup_values_and_targets
        self.default_target = default_target

    __slots__ = ['key', 'low_index', 'high_index', 'targets', 'lookup_values_and_targets', 'default_target']

    def __str__(self):
        return "switch_range(%s) %s default: %s" % (str(self.key),
                                              repr(self.lookup_values_and_targets),
                                              str(self.default_target)
                                              )

    @staticmethod
    def from_ir(label, offset, ir_stmt, stmt_map=None):
        targets = [stmt_map[t] for t in ir_stmt.getTargets()]
        dict_iter = zip(xrange(ir_stmt.getLowIndex(), ir_stmt.getHighIndex() + 1), targets)
        lookup_values_and_targets = {k: v for k, v in dict_iter}

        return TableSwitchStmt(label, offset, SootValue.from_ir(ir_stmt.getKey()), ir_stmt.getLowIndex(),
                               ir_stmt.getHighIndex(), targets,
                               stmt_map[ir_stmt.getDefaultTarget()], lookup_values_and_targets)


class ThrowStmt(SootStmt):
    def __init__(self, label, offset, obj):
        super(ThrowStmt, self).__init__(label, offset)
        self.obj = obj

    __slots__ = ['obj']

    def __str__(self):
        return "Throw(%s)" % str(self.obj)

    @staticmethod
    def from_ir(label, offset, ir_stmt, stmt_map=None):
        return ThrowStmt(label, offset, SootValue.from_ir(ir_stmt.getOp()))


SootStmt.NAME_TO_CLASS = {
    'JAssignStmt': AssignStmt,
    'JBreakpointStmt': BreakpointStmt,
    'JEnterMonitorStmt': EnterMonitorStmt,
    'JExitMonitorStmt': ExitMonitorStmt,
    'JGotoStmt': GotoStmt,
    'JIdentityStmt': IdentityStmt,
    'JIfStmt': IfStmt,
    'JInvokeStmt': InvokeStmt,
    'JLookupSwitchStmt': LookupSwitchStmt,
    'JReturnStmt': ReturnStmt,
    'JReturnVoidStmt': ReturnVoidStmt,
    'JTableSwitchStmt': TableSwitchStmt,
    'JThrowStmt': ThrowStmt,
}

