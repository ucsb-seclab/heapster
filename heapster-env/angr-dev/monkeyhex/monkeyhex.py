from __future__ import print_function
from future.utils import iteritems
from past.builtins import long

DEFAULT_HEX_THRESHOLD = 10**17 # since that hex is more succinct ...
HEX_THRESHOLD = None

def conditional_hex(x):
    if HEX_THRESHOLD is None or abs(x) >= HEX_THRESHOLD:
        return hex(x)
    return repr(x)

def maybe_hex(item, list_depth=0):
    if isinstance(item, bool):
        return repr(item)
    if isinstance(item, (int, long)):
        if _monkeyhex_idapy:
            return '%X' % item
        else:
            return conditional_hex(item)
    elif isinstance(item, (list,)):
        return '[%s]' % joinlist(item, list_depth + 1)
    elif isinstance(item, (set,)):
        return '{%s}' % joinlist(item, list_depth + 1)
    elif isinstance(item, (dict,)):
        return '{%s}' % joindict(item, list_depth + 1)
    elif isinstance(item, (tuple,)):
        return '(%s)' % joinlist(item, list_depth + 1)
    else:
        return repr(item)

def get_joiner(lst, list_depth):
    joiner = ',\n' if len(repr(lst)) > 80 and len(lst) < 400 else ', '
    if joiner[1] == '\n':
        joiner += ' '*list_depth
    return joiner

def joinlist(lst, list_depth):
    return get_joiner(lst, list_depth).join(maybe_hex(a, list_depth) for a in lst)

def joindict(dct, list_depth):
    return get_joiner(dct, list_depth).join(
        '%s: %s' % (maybe_hex(key, list_depth), maybe_hex(val, list_depth))
                for key, val in iteritems(dct)
    )

def hex_print(item):
    if type(item) is bool:
        old_display_hook(item)
        return
    elif item is None:
        old_display_hook(item)
        return

    try:
        class hexprinted(type(item)):
            def __repr__(self):
                return maybe_hex(item)
        old_display_hook(hexprinted(item))
    except:
        old_display_hook(item)

# detect ipython
ipython = False
import inspect
for frame in inspect.stack():
    if 'IPython' in frame[1]:
        ipython = True

_monkeyhex_idapy = False
# detect idapy - note: requires ida 7.3+
try:
    import idaapi
    _monkeyhex_idapy = True
except:
    pass

# monkeypatch the interpreter
if ipython:
    import IPython
    formatter = IPython.get_ipython().display_formatter.formatters['text/plain']
    formatter.for_type(int, lambda n, p, cycle: p.text(conditional_hex(n)))
    if long is not int:
        formatter.for_type(long, lambda n, p, cycle: p.text(conditional_hex(n)))
else:
    import sys
    old_display_hook = sys.displayhook
    sys.displayhook = hex_print

# monkeypatch pprint
import pprint
old_safe_repr = pprint._safe_repr
def safe_hex_repr(obj, context, maxlevels, level):
    if type(obj) in (int, long):
        return conditional_hex(obj), False, False
    else:
        return old_safe_repr(obj, context, maxlevels, level)
pprint._safe_repr = safe_hex_repr

# monkeypatch pdb/ipdb "p" command
import pdb
def hex_p(self, arg):
    try:
        print(maybe_hex(self._getval(arg)), file=self.stdout)
    except: # pylint: disable=bare-except
        pass
pdb.Pdb.do_p = hex_p

# monkeypatch ipdb/ipdb bang-escape
def simple_displayhook(self, obj): # pylint: disable=unused-argument
    if obj is not None:
        print(maybe_hex(obj))
pdb.Pdb.displayhook = simple_displayhook
