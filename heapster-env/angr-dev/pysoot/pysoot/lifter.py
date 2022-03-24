
import os
import logging

from pysoot import *
from .jython_wrapper import JythonWrapper


l = logging.getLogger("pysoot.lifter")
self_dir = os.path.dirname(os.path.realpath(__file__))


class Lifter(object):

    def __init__(self, input_file=None, input_format="jar", ir_format="shimple", additional_jars=None,
                 additional_jar_roots=None, android_sdk=None, save_to_file=None):

        self.input_file = os.path.realpath(input_file)
        self.save_to_file = save_to_file
        allowed_irs = ["shimple", "jimple"]
        if ir_format not in allowed_irs:
            raise ParameterError("ir_format needs to be in " + repr(allowed_irs))
        self.ir_format = ir_format

        allowed_formats = ["jar", "apk"]
        if input_format not in allowed_formats:
            raise ParameterError("format needs to be in " + repr(allowed_formats))
        self.input_format = input_format

        if input_format == "jar":
            if android_sdk is not None:
                l.warning("when input_format is 'jar', setting android_sdk is pointless")
            library_jars = ["rt.jar", "jce.jar"]
            absolute_library_jars = {os.path.realpath(os.path.join(self_dir, "../bin/" + jar)) for jar in library_jars}
            if additional_jars is not None:
                absolute_library_jars |= {os.path.realpath(jar) for jar in additional_jars}
            if additional_jar_roots is not None:
                for jar_root in additional_jar_roots:
                    for jar_name in os.listdir(jar_root):
                        if jar_name.endswith(".jar"):
                            absolute_path = os.path.realpath(os.path.join(jar_root, jar_name))
                            if absolute_path not in absolute_library_jars:
                                absolute_library_jars.add(absolute_path)
            bad_jars = [p for p in absolute_library_jars if ":" in p]
            if len(bad_jars) > 0:
                raise ParameterError("these jars have a semicolon in their name: " + repr(bad_jars))
            self.soot_classpath = ":".join(absolute_library_jars)

        elif input_format == "apk":
            if android_sdk is None:
                raise ParameterError("when format is apk, android_sdk should point to something like: "
                                     "~/Android/Sdk/platforms")
            if additional_jars is not None or additional_jar_roots is not None:
                l.warning("when input_format is 'apk', setting additional_jars or additional_jar_roots is pointless")
            self.android_sdk = android_sdk

        self._get_ir()

    def _get_ir(self):
        config = {}
        settings = ["input_file", "input_format", "ir_format", "android_sdk", "soot_classpath", "main_class"]
        for s in settings:
            config[s] = str(getattr(self, s, None))

        jython_path = os.path.join(self_dir, "jython_bin")
        self.soot_wrapper = JythonWrapper(jython_path, "soot_manager", "SootManager")

        l.info("Running Soot with the following config: " + repr(config))
        self.soot_wrapper.init(config)
        if self.save_to_file is None:
            self.classes = self.soot_wrapper.get_classes()
        else:
            ipc_options = {'return_result': False, 'return_pickle': False, 'save_pickle': self.save_to_file}
            self.classes = self.soot_wrapper.get_classes(_ipc_options=ipc_options)
