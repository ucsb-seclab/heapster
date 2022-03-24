
# this file is executed exclusively in Jython

import sys
import os
import logging
l = logging.getLogger("pysoot.soot_manager")

self_dir = os.path.dirname(os.path.realpath(__file__))
self_dir = self_dir.replace("__pyclasspath__", "")  # needed because added by Jython

# soot-trunk.jar is a slightly modified version of soot. 
# At some point I will upload the modifcations and the compilation script somewhere
sys.path.append(os.path.join(self_dir, "soot-trunk.jar"))
import java.util.Collections as Collections
import soot.Scene as Scene
import soot.Hierarchy as Hierarchy
import soot.G as G
import soot.options.Options as Options
import soot.PackManager as PackManager

# the import situation is pretty complicated
# from a pysoot prospective (running in Python, with a virtualenv with pysoot installed)
# SootClass is in pysoot.sootir.soot_class
# from Jython prospective, without countermeasures, SootClass is in sootir.soot_class
# (because Jython runs without virtualenv and from this folder, so it gets to sootir just following cwd).
# The problem is that when we pickle/unpickle there is a mismatch and Python cannot find sootir.soot_class.
# The solution is that I added a link in jython_bin/Lib to ../pysoot
# (basically simulating a virtualenv in Jython with pysoot installed).
# In this way, Jython can find SootClass by following jython_bin/Lib (which is by default in sys.path) and then
# from pysoot.sootir.soot_class import SootClass
from pysoot.sootir.soot_class import SootClass

class SootManager(object):
    def __init__(self, config):
        G.reset()  # otherwise there are globals around even if a new instance of this class is created!
        # I think there cannot be more than one instance of SootManager around
        # otherwise the globals will conflict
        # it is not a big issue since there is going to be a SootManager instance per Jython process
        self._create_scene(config)

    def _create_scene(self, config):
        Options.v().set_process_dir(Collections.singletonList(config["input_file"]))

        if config["input_format"] == "apk":
            Options.v().set_android_jars(config["android_sdk"])
            Options.v().set_process_multiple_dex(True)
            Options.v().set_src_prec(Options.src_prec_apk)
        elif config["input_format"] == "jar":
            Options.v().set_soot_classpath(config["soot_classpath"])
        else:
            raise Exception("invalid input type")

        if config["ir_format"] == "jimple":
            Options.v().set_output_format(Options.output_format_jimple)
        elif config["ir_format"] == "shimple":
            Options.v().set_output_format(Options.output_format_shimple)
        else:
            raise Exception("invalid ir format")

        Options.v().set_allow_phantom_refs(True)
        
        # this options may or may not work
        Options.v().setPhaseOption("cg", "all-reachable:true")
        Options.v().setPhaseOption("jb.dae", "enabled:false")
        Options.v().setPhaseOption("jb.uce", "enabled:false")
        Options.v().setPhaseOption("jj.dae", "enabled:false")
        Options.v().setPhaseOption("jj.uce", "enabled:false")

        # this avoids an exception in some apks
        Options.v().set_wrong_staticness(Options.wrong_staticness_ignore)

        Scene.v().loadNecessaryClasses()
        PackManager.v().runPacks()
        l.debug("Soot is done!")

        self.scene = Scene.v()
        self.raw_classes = self.scene.getClasses()
        self._init_class_hierarchy()
        l.debug("Soot init is done!")

    def _init_class_hierarchy(self):
        # all methods in Hierarchy.java that take as input one or more SootClass are exported
        # they are wrapped so that they take the name(s) of the classes (as strings)
        # and return a list of class names (as strings) or a boolean
        def make_function(method_name):
            def wrapper(*args):  # no kwargs in a Jython method
                converted_args = [self.raw_class_dict[a] for a in args]
                func = getattr(self.hierarchy, method_name)
                res = func(*converted_args)
                if type(res) == bool:
                    return res
                else:
                    return [c.name for c in res]
            return wrapper

        self.hierarchy = Hierarchy()
        self.raw_class_dict = {cc.name: cc for cc in self.raw_classes}
        exported_class_hierarchy_methods = [n for n in dir(self.hierarchy) if
                                            n not in ["getClass", "isVisible"] and
                                            (n.startswith("get") or n.startswith("is"))]
        for method_name in exported_class_hierarchy_methods:
            setattr(self, method_name, make_function(method_name))

    def get_classes(self):
        classes = {}
        l.debug("Start converting classes")
        for raw_class in self.raw_classes:
            # TODO with this we only get classes for which we have all the code
            # soot also has classes with lower "resolving levels", but for those we may not have
            # the method list or the code, if we want them we cannot fully translate them
            if raw_class.isApplicationClass():
                soot_class = SootClass.from_ir(raw_class)
                classes[soot_class.name] = soot_class
        return classes


if __name__ == "__main__":
    import sys

    config = dict()
    config['input_file'] = sys.argv[3]
    config['android_sdk'] = sys.argv[2]
    config['input_format'] = sys.argv[1]
    config["ir_format"] = "shimple"

    si = SootManager(config)
