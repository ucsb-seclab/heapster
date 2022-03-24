#!/usr/bin/env python 

from pysoot import *

import sys
import os
import logging
import struct
import pickle
import subprocess
import select
import psutil

l = logging.getLogger("pysoot.jython_wrapper")

self_file = os.path.realpath(__file__)
self_dir = os.path.dirname(self_file)


def pkiller():
    from ctypes import cdll
    # PR_SET_PDEATHSIG, SIG_KILL, see: http://www.evans.io/posts/killing-child-processes-on-parent-exit-prctl/
    cdll['libc.so.6'].prctl(1, 9)


class JythonWrapper(object):

    def __init__(self, jython_folder, module_name, class_name, java_heap_size=None):
        self.process = None
        self.jython_folder = jython_folder
        self.class_name = class_name
        self.module_name = module_name
        self.client_stderr = ""
        self.client_stdout = ""
        if java_heap_size is None:
            # use 75% of total memory for the Java heap
            self.java_heap_size = int(psutil.virtual_memory().total*0.75)
        else:
            self.java_heap_size = java_heap_size
        self._start_jython()

    def _start_jython(self):
        self.pipe_read_ctos, self.pipe_write_ctos = os.pipe()
        self.pipe_read_stoc, self.pipe_write_stoc = os.pipe()
        # make pipes accessible from child processes
        os.set_inheritable(self.pipe_write_ctos, True)
        os.set_inheritable(self.pipe_read_stoc, True)
        self.pipe_write_stoc = os.fdopen(self.pipe_write_stoc, 'wb')

        pipe = subprocess.PIPE
        jython_runner_py_file = os.path.join(self_dir, "jython_runner.py")
        # for some reason I cannot pass -Xmx directly to jython (using -J-Xmx), so I start jython from java
        # putting a high Xmx limit basically disables the GC, which may not be ideal
        arg_java_heap_size = "-Xmx"+str(int(self.java_heap_size/float(pow(2, 20))))+"m"
        args = ["java", arg_java_heap_size, "-jar", os.path.join(self.jython_folder, "jython.jar")]
        args += [jython_runner_py_file, self.pipe_write_ctos, self.pipe_read_stoc, self.module_name, self.class_name]
        l.debug(args)

        self.process = subprocess.Popen(map(str, args), stdout=pipe, stderr=pipe, close_fds=False, preexec_fn=pkiller)

    def __getattr__(self, name):
        # this is only called with functions not already defined
        # in this case we need to go remote
        # __init__ is a special case since it is locally defined
        # but we also want a way to call it remotely 
        if name == "init":
            name = "__init__"

        def wrapper(*args, **kwargs):
            # return_result: return the result to the Python caller
            # save_pickle: Jython saves the pickled result in a file
            # return_pickle: return a tuple (result, pickled_result) in Python
            # split_results: if a list or a dict is returned, send N elements at a time (uses less memory)
            # if return_pickle is True results cannot be split (split_results is ignored)
            ipc_option_defaults = {"return_result": True, "save_pickle": None,
                                   "return_pickle": False, "split_results": 10}
            if "_ipc_options" not in kwargs:
                ipc_options = ipc_option_defaults
            else:
                ipc_options = kwargs["_ipc_options"]
                del kwargs["_ipc_options"]
                for k, v in ipc_option_defaults.items():
                    if k not in ipc_options:
                        ipc_options[k] = ipc_option_defaults[k]
                # ipc_options["split_results"] = True
            return self.remote_call((name, args, kwargs, ipc_options))
        return wrapper

    def get_client_std(self, reset=False):
        tstr = "\n".join(["STDOUT:", self.client_stdout, "STDERR:", self.client_stderr])
        if reset:
            self.client_stdout = ""
            self.client_stderr = ""
        return tstr

    def remote_call(self, params):
        l.debug("calling remote function %s (%s)" % (params[0], (params[1:])))
        send_obj(self.pipe_write_stoc, params)
        ipc_options = params[3]
        rdict = {}
        rlist = []
        call_result = None

        l.debug("Unserializing received obj for call %s", params[0])
        while True:
            type_res, buf = self._remote_call_int()
            if ipc_options["return_result"]:
                tres = pickle.loads(buf)
            else:
                tres = None

            if type_res == ord("n"):
                if ipc_options["return_pickle"]:
                    return tres, buf
                else:
                    return tres
            elif type_res == ord("d"):
                rdict.update(tres)
                call_result = rdict
            elif type_res == ord("l"):
                rlist.extend(tres)
                call_result = rlist
            elif type_res == ord("e"):
                return call_result
            elif type_res == "x":
                l.debug("JAVA EXCEPTION:\n"+tres)
                return None


    def _remote_call_int(self):
        rsize = pow(2, 20)
        sockets = [self.process.stderr.fileno(), self.process.stdout.fileno(), self.pipe_read_ctos]
        # l.debug("polling sockets: " + repr(sockets))
        pp = select.poll()
        for ss in sockets:
            pp.register(ss)

        state = 1
        to_recv = 1+8
        buf = b''
        ttype = "n"

        try:
            while True:
                fds_tuples = pp.poll()
                self.process.poll()  # set the return code
                ret_code = self.process.returncode
                # l.debug("poll results: " + repr(fds_tuples) + ", " + repr(ret_code))

                if len(fds_tuples) == 2 and \
                        (self.process.stderr.fileno(), select.EPOLLHUP) in fds_tuples and \
                        (self.process.stdout.fileno(), select.EPOLLHUP) in fds_tuples:
                    # select.EPOLLHUP --> 16, select.EPOLLIN -> 1
                    # stderr and stdout have been closed and nothing else is available
                    if ret_code is not None:
                        estr = "JYTHON DIED %d\n%s" % (ret_code, self.get_client_std())
                        raise JythonClientException(estr)
                    else:
                        estr = "JYTHON SOCKET CLOSED\n%s" % (self.get_client_std())
                        self.process.kill()
                        self.process.poll()
                        raise JythonClientException(estr)

                fds = [f[0] for f in fds_tuples if (f[1] & select.EPOLLIN) != 0]
                # time.sleep(0.1)
                if self.process.stderr.fileno() in fds:
                    tstr = os.read(self.process.stderr.fileno(), rsize)
                    self.client_stderr += str(tstr)
                if self.process.stdout.fileno() in fds:
                    tstr = os.read(self.process.stdout.fileno(), rsize)
                    self.client_stdout += str(tstr)
                if self.pipe_read_ctos in fds:
                    # os.read wants as readn at most a signed int
                    readn = min(to_recv, pow(2, 30))
                    tstr = os.read(self.pipe_read_ctos, readn)
                    # l.debug("reading from Jython: %d %d %d %d" % (to_recv, readn, len(tstr), len(buf)))
                    to_recv -= len(tstr)
                    buf += tstr
                    if to_recv == 0:
                        if state == 1:
                            to_recv = struct.unpack("<Q", buf[1:])[0]
                            ttype = buf[0]
                            buf = b""
                            state = 2
                        elif state == 2:
                            return ttype, buf

        except KeyboardInterrupt:
            estr = "JYTHON CLIENT INTERRUPTED\n%s" % (self.get_client_std())
            self.process.kill()
            self.process.poll()
            raise KeyboardInterrupt(estr)

        finally:
            # this seems to restore the shell to a usable state
            subprocess.Popen(["stty", "sane"]).communicate()

    def __del__(self):
        if self.process is not None:
            try:
                self.process.kill()
                self.process.poll()
            except OSError:  # the process died before
                pass
        import subprocess
        # this seems to restore the shell to a usable state
        subprocess.Popen(["stty", "sane"]).communicate()


if __name__ == "__main__":
    if sys.argv[1] == "test":
        # import IPython; IPython.embed()

        logging.getLogger("python.jython_wrapper")
        logging.basicConfig(level=logging.DEBUG)

        jython_path = os.path.join(self_dir, "jython_bin")
        jt_instance = JythonWrapper(jython_path, "", "Test1");
        res = jt_instance.init(2, 3)
        print(jt_instance.get_client_std(True)) # the timing of what appears here may change
        print("res: ", res)
        res = jt_instance.increase(4)
        print(jt_instance.get_client_std(True))
        print("res: ", res)
        res = jt_instance.increase(5)
        print(jt_instance.get_client_std(True))
        print("res: ", res)
        # res = jt_instance.exception()
        res = jt_instance.__exit("msg1")
        print(jt_instance.get_client_std(True))
        print("res: ", res)

    elif sys.argv[1] == "ipython":
        logging.getLogger("python.jython_wrapper")
        logging.basicConfig(level=logging.DEBUG)
        import IPython; IPython.embed()
