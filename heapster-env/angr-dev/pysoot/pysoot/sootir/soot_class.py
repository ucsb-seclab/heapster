
from . import convert_soot_attributes
import copy


class SootClass(object):

    __slots__ = ['name', 'super_class', 'interfaces', 'attrs', 'methods', 'fields']

    def __init__(self, name, super_class, interfaces, attrs, methods, fields):
        self.name = name
        self.super_class = super_class
        self.interfaces = interfaces
        self.attrs = attrs
        self.methods = methods
        self.fields = fields

    def __str__(self):
        tstr = "//" + repr(self) + "\n"
        tstr += " ".join([a.lower() for a in self.attrs]) + " class " + self.name + " extends " + self.super_class
        if self.interfaces:
            tstr += " implements " + ", ".join(self.interfaces)
        tstr += "{\n"

        for field_name, field_value in self.fields.items():
            tstr += "\t" + " ".join([f.lower() for f in field_value[0]]) + " " + field_value[1] + " " + field_name + "\n"
        tstr += "\n"

        for m in self.methods:
            tstr += "\n".join(["\t"+line for line in str(m).split("\n")]) + "\n"

        tstr += "}\n"
        return tstr

    @staticmethod
    def from_ir(ir_class):
        methods = []
        class_name = ir_class.getName()

        method_list = copy.copy(ir_class.getMethods())
        for ir_method in method_list:
            methods.append(SootMethod.from_ir(class_name, ir_method))

        attrs = convert_soot_attributes(ir_class.getModifiers())
        extra_attrs = "LibraryClass", "JavaLibraryClass", "Phantom"
        for e in extra_attrs:
            method = getattr(ir_class, "is"+e)
            if method():
                attrs.append(e)

        fields = {}
        for field in ir_class.getFields():
            fields[field.getName()] = (convert_soot_attributes(field.getModifiers()), str(field.getType()))

        interface_names = [it.getName() for it in ir_class.getInterfaces()]
        if class_name != "java.lang.Object":
            super_class = ir_class.getSuperclass().getName()
        else:
            super_class = ""
        return SootClass(class_name, super_class, interface_names, attrs, methods, fields)

from .soot_method import SootMethod
