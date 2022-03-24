Monkeyhex
=========

`monkeyhex.py` is a small library to assist users of the python shell who work
in contexts where printed numbers are more usefully viewed in hexadecimal.

Monkeyhex will format the results of statements in the python interactive shell
in hex. To use it, just import the library and all future results will be
formatted. To view a result in decimal again, put the expression in a print
statement.

In addition, Monkeyhex implements a `pprint`-like pretty-printing of long lists
and dictionaries.
```python
Python 2.7.6 (default, Mar 22 2014, 22:59:56) 
[GCC 4.8.2] on linux2
Type "help", "copyright", "credits" or "license" for more information.
>>> 1024
1024
>>> import monkeyhex
>>> 1024
0x400
>>> print 1024
1024
>>> [2**x for x in range(20)]
[0x1,
 0x2,
 0x4,
 0x8,
 0x10,
 0x20,
 0x40,
 0x80,
 0x100,
 0x200,
 0x400,
 0x800,
 0x1000,
 0x2000,
 0x4000,
 0x8000,
 0x10000,
 0x20000,
 0x40000,
 0x80000]
>>> 
```

Installation
------------

```bash
pip install monkeyhex
```
