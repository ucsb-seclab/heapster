from .soot_value import SootValue


class SootExpr(SootValue):
    NAME_TO_CLASS = {}

    def __init__(self, type_):
        super(SootExpr, self).__init__(type_)

    __slots__ = []

    @staticmethod
    def from_ir(ir_expr):
        subtype = ir_expr.getClass().getSimpleName()
        cls = SootExpr.NAME_TO_CLASS.get(subtype, None)
        if cls is None:
            raise NotImplementedError('Unsupported Soot expression type %s.' % subtype)

        return cls.from_ir(str(ir_expr.getType()), subtype, ir_expr)


class SootBinopExpr(SootExpr):
    def __init__(self, type_, op, value1, value2):
        super(SootBinopExpr, self).__init__(type_)
        self.op = op
        self.value1 = value1
        self.value2 = value2

    __slots__ = ['op', 'value1', 'value2']

    def __str__(self):
        return "%s %s %s" % (str(self.value1), SootExpr.OP_TO_STR[self.op], str(self.value2))

    @staticmethod
    def from_ir(type_, expr_name, ir_subvalue):
        op = expr_name[1:].replace("Expr", "").lower()

        return SootBinopExpr(type_, op, SootValue.from_ir(ir_subvalue.getOp1()),
                             SootValue.from_ir(ir_subvalue.getOp2()))


class SootUnopExpr(SootExpr):
    def __init__(self, type_, op, value):
        super(SootUnopExpr, self).__init__(type_)
        self.op = op
        self.value = value

    __slots__ = ['op', 'value']

    def __str__(self):
        return "%s %s" % (SootExpr.OP_TO_STR[self.op], str(self.value))

    @staticmethod
    def from_ir(type_, expr_name, ir_subvalue):
        op = expr_name[1:].replace("Expr", "").lower()
        return SootUnopExpr(type_, op, SootValue.from_ir(ir_subvalue.getOp()))


class SootCastExpr(SootExpr):
    def __init__(self, type_, cast_type, value):
        super(SootCastExpr, self).__init__(type_)
        self.cast_type = cast_type
        self.value = value

    __slots__ = ['cast_type', 'value']

    def __str__(self):
        return "((%s) %s)" % (str(self.cast_type), str(self.value))

    @staticmethod
    def from_ir(type_, expr_name, ir_subvalue):

        return SootCastExpr(type_, str(ir_subvalue.getCastType()), SootValue.from_ir(ir_subvalue.getOp()))


class SootConditionExpr(SootExpr):
    def __init__(self, type_, op, value1, value2):
        super(SootConditionExpr, self).__init__(type_)
        self.op = op
        self.value1 = value1
        self.value2 = value2

    __slots__ = ['op', 'value1', 'value2']

    def __str__(self):
        return "%s %s %s" % (str(self.value1), SootExpr.OP_TO_STR[self.op], str(self.value2))

    @staticmethod
    def from_ir(type_, expr_name, ir_subvalue):
        op = expr_name[1:].replace("Expr", "").lower()
        return SootConditionExpr(type_, op, SootValue.from_ir(ir_subvalue.getOp1()),
                                 SootValue.from_ir(ir_subvalue.getOp2()))


class SootLengthExpr(SootExpr):
    def __init__(self, type_, value):
        super(SootLengthExpr, self).__init__(type_)
        self.value = value

    __slots__ = ['value']

    def __str__(self):
        return "len(%s)" % str(self.value)

    @staticmethod
    def from_ir(type_, expr_name, ir_subvalue):
        return SootLengthExpr(type_, SootValue.from_ir(ir_subvalue.getOp()))


class SootNewArrayExpr(SootExpr):
    def __init__(self, type_, base_type, size):
        super(SootNewArrayExpr, self).__init__(type_)
        self.base_type = base_type
        self.size = size

    __slots__ = ['base_type', 'size']

    def __repr__(self):
        return "SootNewArrayExpr(%s[%s])" % (self.base_type, self.size)

    def __str__(self):
        return "new %s[%s]" % (self.base_type, str(self.size))

    @staticmethod
    def from_ir(type_, expr_name, ir_subvalue):
        return SootNewArrayExpr(type_, str(ir_subvalue.getBaseType()), SootValue.from_ir(ir_subvalue.getSize()))


class SootNewMultiArrayExpr(SootExpr):
    def __init__(self, type_, base_type, sizes):
        super(SootNewMultiArrayExpr, self).__init__(type_)
        self.base_type = base_type
        self.sizes = sizes

    __slots__ = ['base_type', 'sizes']

    def __str__(self):
        return "new %s%s" % (self.base_type.replace("[", "").replace("]", ""),
                             "".join((["[%s]" % str(s) for s in self.sizes])))

    @staticmethod
    def from_ir(type_, expr_name, ir_subvalue):
        return SootNewMultiArrayExpr(type_, str(ir_subvalue.getBaseType()),
                                     [SootValue.from_ir(size) for size in ir_subvalue.getSizes()])


class SootNewExpr(SootExpr):
    def __init__(self, type_, base_type):
        super(SootNewExpr, self).__init__(type_)
        self.base_type = base_type

    __slots__ = ['base_type']

    def __str__(self):
        return "new %s" % str(self.base_type)

    @staticmethod
    def from_ir(type_, expr_name, ir_subvalue):
        return SootNewExpr(type_, str(ir_subvalue.getBaseType()))


class SootPhiExpr(SootExpr):
    def __init__(self, type_, values):
        super(SootPhiExpr, self).__init__(type_)
        self.values = values

    __slots__ = ['values']

    def __str__(self):
        return "Phi(%s)" % (", ".join(['{} #{}'.format(s, b_id) for s, b_id in self.values]))

    @staticmethod
    def from_ir(type_, expr_name, ir_subvalue):
        return SootPhiExpr(type_, [SootValue.from_ir(v.getValue()) for v in ir_subvalue.getArgs()])


# every invoke type has a method signature (class + name + parameter types) and concrete arguments
# all invoke types, EXCEPT static, have a base ("this" concrete instance)
class SootInvokeExpr(SootExpr):
    def __init__(self, type_, class_name, method_name, method_params, args):
        super(SootInvokeExpr, self).__init__(type_)
        self.class_name = class_name
        self.method_name = method_name
        self.method_params = method_params
        self.args = args

    __slots__ = ['class_name', 'method_name', 'method_params', 'args']

    def __str__(self):
        return "%s.%s(%s)]" % (self.class_name, self.method_name, self.list_to_arg_str(self.method_params))

    @staticmethod
    def list_to_arg_str(args):
        return ", ".join(map(str, args))


class SootVirtualInvokeExpr(SootInvokeExpr):
    def __init__(self, type_, class_name, method_name, method_params, base, args):
        super(SootVirtualInvokeExpr, self).__init__(type_, class_name, method_name, method_params, args)
        self.base = base

    __slots__ = ['base']

    def __str__(self):
        return "%s.%s(%s) [virtualinvoke %s" % (str(self.base), self.method_name, self.list_to_arg_str(self.args),
                                                str(super(SootVirtualInvokeExpr, self).__str__()))

    @staticmethod
    def from_ir(type_, expr_name, ir_expr):
        args = tuple([SootValue.from_ir(arg) for arg in ir_expr.getArgs()])
        called_method = ir_expr.getMethod()
        params = tuple([str(param) for param in called_method.getParameterTypes()])

        return SootVirtualInvokeExpr(type_, str(called_method.getDeclaringClass().getName()),
                                     str(called_method.getName()),
                                     params, SootValue.from_ir(ir_expr.getBase()), args)


class SootDynamicInvokeExpr(SootInvokeExpr):
    def __init__(self, type_, class_name, method_name, method_params, method_args, bootstrap_method, bootstrap_args):
        super(SootDynamicInvokeExpr, self).__init__(type_, class_name, method_name, method_params, method_args)

        self.bootstrap_method = bootstrap_method
        self.bootstrap_args = bootstrap_args

    @staticmethod
    def from_ir(type_, expr_name, ir_expr):
        bootstrap_method = None #ir_expr.getBootstrapMethod()
        bootstrap_args = None # tuple([ SootValue.from_ir(arg) for arg in ir_expr.getBootstrapArgs() ])
        method = ir_expr.getMethod()
        method_params = tuple([str(param) for param in method.getParameterTypes()])
        method_args = tuple([SootValue.from_ir(arg) for arg in ir_expr.getArgs()])

        class_name = str(method.getDeclaringClass().getName())
        method_name = str(method.getName())

        return SootDynamicInvokeExpr(type_, class_name, method_name, method_params, method_args, bootstrap_method,
                                     bootstrap_args)


class SootInterfaceInvokeExpr(SootInvokeExpr):
    def __init__(self, type_, method_class, method_name, method_params, base, args):
        super(SootInterfaceInvokeExpr, self).__init__(type_, method_class, method_name, method_params, args)
        self.base = base

    __slots__ = ['base']

    def __str__(self):
        return "%s.%s(%s) [interfaceinvoke %s" % (str(self.base), self.method_name, self.list_to_arg_str(self.args),
                                                  str(super(SootInterfaceInvokeExpr, self).__str__()))

    @staticmethod
    def from_ir(type_, expr_name, ir_expr):
        args = tuple([SootValue.from_ir(arg) for arg in ir_expr.getArgs()])
        called_method = ir_expr.getMethod()
        params = tuple([str(param) for param in called_method.getParameterTypes()])

        return SootInterfaceInvokeExpr(type_, str(called_method.getDeclaringClass().getName()),
                                       str(called_method.getName()),
                                       params, SootValue.from_ir(ir_expr.getBase()), args)


class SootSpecialInvokeExpr(SootInvokeExpr):
    def __init__(self, type_, class_name, method_name, method_params, base, args):
        super(SootSpecialInvokeExpr, self).__init__(type_, class_name, method_name, method_params, args)
        self.base = base

    __slots__ = ['base']

    def __str__(self):
        return "%s.%s(%s) [specialinvoke %s" % (str(self.base), self.method_name, self.list_to_arg_str(self.args),
                                                str(super(SootSpecialInvokeExpr, self).__str__()))

    @staticmethod
    def from_ir(type_, expr_name, ir_expr):
        args = tuple([SootValue.from_ir(arg) for arg in ir_expr.getArgs()])
        called_method = ir_expr.getMethod()
        params = tuple([str(param) for param in called_method.getParameterTypes()])

        return SootSpecialInvokeExpr(type_, str(called_method.getDeclaringClass().getName()),
                                     str(called_method.getName()),
                                     params, SootValue.from_ir(ir_expr.getBase()), args)


class SootStaticInvokeExpr(SootInvokeExpr):
    def __init__(self, type_, method_class, method_name, method_params, args):
        super(SootStaticInvokeExpr, self).__init__(type_, method_class, method_name, method_params, args)

    __slots__ = []

    def __str__(self):
        return "%s(%s) [staticinvoke %s" % (self.method_name, self.list_to_arg_str(self.args),
                                            str(super(SootStaticInvokeExpr, self).__str__()))

    @staticmethod
    def from_ir(type_, expr_name, ir_expr):
        args = tuple([SootValue.from_ir(arg) for arg in ir_expr.getArgs()])
        called_method = ir_expr.getMethod()
        params = tuple([str(param) for param in called_method.getParameterTypes()])

        return SootStaticInvokeExpr(type_, str(called_method.getDeclaringClass().getName()),
                                    str(called_method.getName()), params, args)


class SootInstanceOfExpr(SootValue):
    def __init__(self, type_, check_type, value):
        super(SootInstanceOfExpr, self).__init__(type_)
        self.check_type = check_type
        self.value = value

    __slots__ = ['check_type', 'value']

    def __str__(self):
        return "%s instanceof %s" % (str(self.value), str(self.check_type))

    @staticmethod
    def from_ir(type_, expr_name, ir_expr):
        return SootInstanceOfExpr(type_, str(ir_expr.getCheckType()), SootValue.from_ir(ir_expr.getOp()))


SootExpr.NAME_TO_CLASS = {
    'JCastExpr': SootCastExpr,
    'JLengthExpr': SootLengthExpr,
    'JNewExpr': SootNewExpr,
    'JNewArrayExpr': SootNewArrayExpr,
    'JNewMultiArrayExpr': SootNewMultiArrayExpr,
    'JInstanceOfExpr': SootInstanceOfExpr,

    'SPhiExpr': SootPhiExpr,

    'JDynamicInvokeExpr': SootDynamicInvokeExpr,
    'JInterfaceInvokeExpr': SootInterfaceInvokeExpr,
    'JSpecialInvokeExpr': SootSpecialInvokeExpr,
    'JStaticInvokeExpr': SootStaticInvokeExpr,
    'JVirtualInvokeExpr': SootVirtualInvokeExpr,

    'JEqExpr': SootConditionExpr,
    'JGeExpr': SootConditionExpr,
    'JGtExpr': SootConditionExpr,
    'JLeExpr': SootConditionExpr,
    'JLtExpr': SootConditionExpr,
    'JNeExpr': SootConditionExpr,
    'JNegExpr': SootUnopExpr,

    'JAddExpr': SootBinopExpr,
    'JAndExpr': SootBinopExpr,
    'JCmpExpr': SootBinopExpr,
    'JCmpgExpr': SootBinopExpr,
    'JCmplExpr': SootBinopExpr,
    'JDivExpr': SootBinopExpr,
    'JMulExpr': SootBinopExpr,
    'JOrExpr': SootBinopExpr,
    'JRemExpr': SootBinopExpr,
    'JShlExpr': SootBinopExpr,
    'JShrExpr': SootBinopExpr,
    'JSubExpr': SootBinopExpr,
    'JUshrExpr': SootBinopExpr,
    'JXorExpr': SootBinopExpr,
}

SootExpr.OP_TO_STR = {
    'eq': '==',
    'ge': '>=',
    'gt': '>',
    'le': '<=',
    'lt': '<',
    'ne': '!=',
    'neg': '!',

    'add': '+',
    'and': '&',
    'cmp': 'cmp',
    'cmpg': 'cmpg',
    'cmpl': 'cmpl',
    'div': '/',
    'mul': '*',
    'or': '|',
    'rem': '%',
    'shl': '<<',
    'shr': '>>',
    'sub': '-',
    'ushr': '>>>',
    'xor': '^',
}

'''
cc = open("pysoot/soot/soot_expr.py").read()
state = 0
slots = []
outf = open("/tmp/ttt.py","wb")
for l in cc.split("\n"):
    if l.startswith("    def __init__"):
        state = 1
    elif state == 1 and l.startswith("    def"):
        state = 0
        ll = "    __slots__ = " + repr(slots)
        print ll
        outf.write(ll+"\n\n")
        slots = []
    elif state == 1 and l.startswith("        self."):
        slots.append(l.split("self.")[1].split()[0].strip())
    outf.write(l+"\n")
outf.close()
'''
