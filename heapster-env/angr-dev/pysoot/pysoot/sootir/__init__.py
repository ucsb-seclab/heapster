
'''
import requests
rr = requests.get("https://raw.githubusercontent.com/Sable/soot/develop/src/soot/Modifier.java")
d = {}
for l in rr.text.encode("ascii","ignore").split("\n"):
    if "public static final int" in l:
        l = l.split(";")[0].strip()
        l,_, r = l.partition("=")
        d[int(r,16)] = l.split("int")[1].strip()
for k,v in sorted(d.iteritems()):
    print hex(k).rjust(8)+": " + "'" +v + "',"
'''

attribute_conversion_dict = {
         0x1: 'PUBLIC',
         0x2: 'PRIVATE',
         0x4: 'PROTECTED',
         0x8: 'STATIC',
        0x10: 'FINAL',
        0x20: 'SYNCHRONIZED',
        0x40: 'VOLATILE',
        0x80: 'TRANSIENT',
       0x100: 'NATIVE',
       0x200: 'INTERFACE',
       0x400: 'ABSTRACT',
       0x800: 'STRICTFP',
      0x1000: 'SYNTHETIC',
      0x2000: 'ANNOTATION',
      0x4000: 'ENUM',
     0x10000: 'CONSTRUCTOR',
     0x20000: 'DECLARED_SYNCHRONIZED'
}
attribute_conversion_dict_inv = {v: k for k, v in attribute_conversion_dict.items()}


def convert_soot_attributes(attributes):
    attr_list = []
    v = 1
    while v <= max(attribute_conversion_dict.keys()):
        if (attributes & v) != 0:
            attr_list.append(attribute_conversion_dict[v])
        v <<= 1

    return attr_list

