
from pysoot import *

import sys
import logging
import importlib
import traceback

l = logging.getLogger("pysoot.jython_runner")


class JythonRunner(object):

    def __init__(self, pipe_write_ctos, pipe_read_stoc, module_name, class_name):
        self.class_name = class_name
        self.module_name = module_name
        self.pipe_write_ctos = open("/proc/self/fd/"+str(pipe_write_ctos), "wb")
        self.pipe_read_stoc = open("/proc/self/fd/"+str(pipe_read_stoc), "rb")

    @staticmethod
    def _class_for_name(module_name, class_name):
        # https://stackoverflow.com/questions/1176136/convert-string-to-python-class-object
        if module_name == "":
            mname = __name__
        else:
            mname = module_name
        # load the module, will raise ImportError if module cannot be loaded
        m = importlib.import_module(mname)
        # get the class, will raise AttributeError if class cannot be found
        c = getattr(m, class_name)
        return c

    def main_loop(self):
        created_class = self._class_for_name(self.module_name, self.class_name)
        instance = None
        l.debug("created class " + repr(created_class))

        # TODO implement IPC also for exceptions
        while True:
            r = recv_obj(self.pipe_read_stoc)
            l.debug("received command: " + repr(r))
            func_name = r[0]
            if func_name == "__exit":
                l.debug("received __exit command: " + repr(r[1:]))
                send_obj(self.pipe_write_ctos, None)
                break
            elif func_name == "__init__":
                instance = created_class(*r[1], **r[2])
                send_obj(self.pipe_write_ctos, None)
            else:

                ipc_options = r[3]
                send_back = (ipc_options["return_result"] or ipc_options["return_pickle"])

                # we do getattr on the instance, so that we can also get methods
                # dynamically attached to the instance
                # because of this, func already "closes" 'self'
                # so we don't need to pass instance to func as a parameter
                func = getattr(instance, func_name)
                try:
                    res = func(*r[1], **r[2])
                except:
                    if send_back:
                        send_obj(self.pipe_write_ctos, traceback.format_exc(), otype="x")
                else:

                    if ipc_options["save_pickle"] is not None:
                        with open(ipc_options["save_pickle"], "wb") as fp:
                            if send_back:
                                pickled_object = pickle.dumps(res, PICKLE_PROTOCOL)
                                fp.write(pickled_object)
                                fp.flush()
                                send_obj(self.pipe_write_ctos, None, pickled_object)
                            else:
                                pickle.dump(res, fp, PICKLE_PROTOCOL)
                                fp.flush()
                                send_obj(self.pipe_write_ctos, None)
                    else:
                        if send_back:
                            if not ipc_options["split_results"] or ipc_options["return_pickle"]:
                                send_obj(self.pipe_write_ctos, res)
                            else:
                                if type(res) == dict:
                                    nel = max(1, len(res) / ipc_options["split_results"])
                                    send_obj(self.pipe_write_ctos, {}, otype="d")
                                    for i in xrange(0, len(res), nel):
                                        send_obj(self.pipe_write_ctos, dict(res.items()[i:i+nel]), otype="d")
                                elif type(res) == list:
                                    nel = max(1, len(res) / ipc_options["split_results"])
                                    send_obj(self.pipe_write_ctos, [], otype="l")
                                    for i in xrange(0, len(res), nel):
                                        send_obj(self.pipe_write_ctos, res[i:i+nel], otype="l")
                                send_obj(self.pipe_write_ctos, None, otype="e")
                        else:
                            send_obj(self.pipe_write_ctos, None)


if __name__ == "__main__":
    if not is_jython():
        print("This code should run in Jython")
        sys.exit(1)
    else:
        logging.basicConfig(format='%(levelname)-7s | %(asctime)-23s | %(name)-8s | %(message)s', level=logging.DEBUG)
        jc = JythonRunner(int(sys.argv[1]), int(sys.argv[2]), sys.argv[3], sys.argv[4])
        jc.main_loop()
