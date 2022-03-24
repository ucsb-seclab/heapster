
import sys


def is_jython():
    ee = sys.executable
    # it is None when you start Jython from Java
    return ee is None or ee.endswith("jython")


from .errors import *
import struct
import pickle

PICKLE_PROTOCOL = 2

def send_obj(fp, obj, pickled_object=None, otype = b"n"):
    # TODO is there a faster/less memory-consuming method than using a pipe
    # what about pickle + shared memory?
    if pickled_object is None:
        pickled_object = pickle.dumps(obj, PICKLE_PROTOCOL)
    full_data = otype + struct.pack("<Q", len(pickled_object)) + pickled_object
    fp.write(full_data)
    fp.flush()


def recv_obj(fp):
    state = 1
    to_recv = 1+8
    buf = ""
    while True:
        tstr = fp.read(to_recv)
        if tstr == "":
            raise RecvException()
        to_recv -= len(tstr)
        buf += tstr
        if to_recv == 0:
            if state == 1:
                to_recv = struct.unpack("<Q", buf[1:])[0]
                buf = ""
                state = 2
            elif state == 2:
                return pickle.loads(buf)
