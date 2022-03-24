
class SootValue(object):

    NAME_TO_CLASS = {}
    IREXPR_TO_EXPR = {}

    def __init__(self, type_):
        self.type = type_

    __slots__ = ['type']

    def __str__(self):
        return str(self.type)

    @staticmethod
    def from_ir(ir_value):
        subtype = ir_value.getClass().getSimpleName()
        subtype = subtype.replace("Jimple", "").replace("Shimple", "")

        if subtype.endswith('Expr'):
            expr = SootExpr.from_ir(ir_value)
            SootValue.IREXPR_TO_EXPR[ir_value] = expr
            return expr

        cls = SootValue.NAME_TO_CLASS.get(subtype, None)

        if cls is None:
            raise NotImplementedError('Unsupported SootValue type %s.' % subtype)

        return cls.from_ir(str(ir_value.getType()), ir_value)


class SootLocal(SootValue):
    def __init__(self, type_, name):
        super(SootLocal, self).__init__(type_)
        self.name = name

    __slots__ = ['name']

    def __str__(self):
        return self.name

    @staticmethod
    def from_ir(type_, ir_value):
        return SootLocal(type_, ir_value.getName())


class SootArrayRef(SootValue):
    def __init__(self, type_, base, index):
        super(SootArrayRef, self).__init__(type_)
        self.base = base
        self.index = index

    __slots__ = ['base', 'index']

    def __str__(self):
        return "%s[%s]" % (self.base, self.index)

    @staticmethod
    def from_ir(type_, ir_value):
        return SootArrayRef(type_, SootValue.from_ir(ir_value.getBase()), SootValue.from_ir(ir_value.getIndex()))


class SootCaughtExceptionRef(SootValue):
    def __init__(self, type_):
        super(SootCaughtExceptionRef, self).__init__(type_)

    __slots__ = []

    def __str__(self):
        return "Caught(%s)" % str(super(SootCaughtExceptionRef, self).__str__())

    @staticmethod
    def from_ir(type_, ir_value):
        return SootCaughtExceptionRef(type_)


class SootParamRef(SootValue):
    def __init__(self, type_, index):
        super(SootParamRef, self).__init__(type_)
        self.index = index
        self.type = type_

    __slots__ = ['index']

    def __str__(self):
        return "@parameter%d[%s]" % (self.index, self.type)

    @staticmethod
    def from_ir(type_, ir_value):
        return SootParamRef(type_, ir_value.getIndex())


class SootThisRef(SootValue):
    def __init__(self, type_):
        super(SootThisRef, self).__init__(type_)

    __slots__ = []

    def __str__(self):
        return "@this[%s]" % str(self.type)

    @staticmethod
    def from_ir(type_, ir_value):
        return SootThisRef(type_)


class SootStaticFieldRef(SootValue):
    def __init__(self, type_, field):
        super(SootStaticFieldRef, self).__init__(type_)
        self.field = (field.getName(), field.getDeclaringClass().getName())

    __slots__ = ['field']

    def __str__(self):
        return "StaticFieldRef %s" % (self.field, )

    @staticmethod
    def from_ir(type_, ir_value):
        return SootStaticFieldRef(type_, ir_value.getField())


class SootInstanceFieldRef(SootValue):
    def __init__(self, type_, base, field):
        super(SootInstanceFieldRef, self).__init__(type_)
        self.base = base
        self.field = (field.getName(), field.getDeclaringClass().getName())

    __slots__ = ['base', 'field']

    def __str__(self):
        return "%s.%s" % (str(self.base), str(self.field))

    @staticmethod
    def from_ir(type_, ir_value):
        return SootInstanceFieldRef(type_, SootValue.from_ir(ir_value.getBase()), ir_value.getField())


class SootClassConstant(SootValue):
    def __init__(self, type_, value):
        super(SootClassConstant, self).__init__(type_)
        self.value = str(value)

    __slots__ = ['value']

    def __str__(self):
        return str(self.value)

    @staticmethod
    def from_ir(type_, ir_value):
        return SootClassConstant(type_, ir_value)


class SootDoubleConstant(SootValue):
    def __init__(self, type_, value):
        super(SootDoubleConstant, self).__init__(type_)
        self.value = float(str(value).replace("D", "").replace("#", ""))

    __slots__ = ['value']

    def __str__(self):
        return str(self.value)+"d"

    @staticmethod
    def from_ir(type_, ir_value):
        return SootDoubleConstant(type_, ir_value)


class SootFloatConstant(SootValue):
    def __init__(self, type_, value):
        super(SootFloatConstant, self).__init__(type_)
        self.value = float(str(value).replace("F", "").replace("#", ""))

    __slots__ = ['value']

    def __str__(self):
        return str(self.value)+"f"

    @staticmethod
    def from_ir(type_, ir_value):
        return SootFloatConstant(type_, ir_value)


class SootIntConstant(SootValue):
    def __init__(self, type_, value):
        super(SootIntConstant, self).__init__(type_)
        self.value = int(str(value))

    __slots__ = ['value']

    def __str__(self):
        return str(self.value)

    @staticmethod
    def from_ir(type_, ir_value):
        return SootIntConstant(type_, ir_value)


class SootLongConstant(SootValue):
    def __init__(self, type_, value):
        super(SootLongConstant, self).__init__(type_)
        self.value = long(str(value).replace("L", ""))

    __slots__ = ['value']

    def __str__(self):
        return str(self.value)

    @staticmethod
    def from_ir(type_, ir_value):
        return SootLongConstant(type_, ir_value)


class SootNullConstant(SootValue):
    def __init__(self, type_):
        super(SootNullConstant, self).__init__(type_)

    __slots__ = []

    def __str__(self):
        return "null"

    @staticmethod
    def from_ir(type_, ir_value):
        return SootNullConstant(type_)


class SootStringConstant(SootValue):
    def __init__(self, type_, value):
        super(SootStringConstant, self).__init__(type_)
        self.value = str(value)

    __slots__ = ['value']

    def __str__(self):
        # this automatically adds quotes and escape weird characters using Python-style
        return repr(self.value)

    @staticmethod
    def from_ir(type_, ir_value):
        return SootStringConstant(type_, ir_value)


SootValue.NAME_TO_CLASS = {
    'Local': SootLocal,

    'JArrayRef': SootArrayRef,
    'JCaughtExceptionRef': SootCaughtExceptionRef,
    'JInstanceFieldRef': SootInstanceFieldRef,
    'ParameterRef': SootParamRef,
    'ThisRef': SootThisRef,
    'StaticFieldRef': SootStaticFieldRef,

    'ClassConstant': SootClassConstant,
    'DoubleConstant': SootDoubleConstant,
    'FloatConstant': SootFloatConstant,
    'IntConstant': SootIntConstant,
    'LongConstant': SootLongConstant,
    'NullConstant': SootNullConstant,
    'StringConstant': SootStringConstant,
}

from .soot_expr import SootExpr

