import angr
import logging
import networkx
import os 
import struct

from threading import Timer

import angr.analyses.reaching_definitions.dep_graph as dep_graph

from angr.engines.light import SpOffset, RegisterOffset
from angr.knowledge_plugins.key_definitions.atoms import Register, SpOffset, MemoryLocation
from angr.knowledge_plugins.key_definitions.undefined import undefined, Undefined
from angr.knowledge_plugins.key_definitions.definition import Definition, ParamTag, RetValueTag, InitValueTag
from angr.knowledge_plugins.key_definitions.dataset import DataSet

from heapster.utils import *

l = logging.getLogger("heapster.arguments_analyses.unused_args_analysis")
#l.setLevel(logging.DEBUG)

OP_BEFORE = 0
OP_AFTER  = 1

def get_param_uses(rd, arg_reg_offest):
    for reg_def in rd.all_uses._uses_by_definition.keys():
        if type(reg_def.atom) == Register:
            if reg_def.atom.reg_offset == arg_reg_offest and reg_def.tag and type(reg_def.tag) == ParamTag:
                uses = rd.all_uses._uses_by_definition[reg_def]
                return uses

def filter_unused_args(project, func):
    observation_points = [ ("insn", project.factory.block(addr=blocknode.addr, opt_level=1).instruction_addrs[-1], OP_BEFORE) for blocknode in func.endpoints]
    real_args = []

    try:
        rd = project.analyses.ReachingDefinitions(subject=func, 
                                                  func_graph=func.graph,
                                                  cc = func.calling_convention,
                                                  observation_points= observation_points,
                                                 )
    except Exception as e:
        l.critical("RD exception during unused_args_analysis")
        
        if func.calling_convention is not None:
            for x in func.calling_convention.args:
                if type(x) == angr.calling_conventions.SimRegArg:
                    real_args.append(x.reg_name)
            return real_args
        else:
            return real_args

    if rd.observed_results != {}:
        if func.calling_convention:
            for func_arg in func.calling_convention.args:
                if type(func_arg) != angr.calling_conventions.SimRegArg:
                    continue
                l.info("Analyzing arg {} of func at {}".format(func_arg.reg_name, hex(func.addr)))
                arg_reg_offest = reg_to_offset(project, func_arg.reg_name) 
                arg_uses = get_param_uses(rd, arg_reg_offest)
                if arg_uses == None:
                    l.info("Arg {} is never used".format(func_arg.reg_name))
                    l.info("Assuming the following one are not too. Done.")
                    return real_args
                else:
                    l.info("Arg is used at {}".format(arg_uses))
                    real_args.append(func_arg.reg_name)
            return real_args
    
    return real_args


def get_args_uses(project, func):
    observation_points = [ ("insn", project.factory.block(addr=blocknode.addr, opt_level=1).instruction_addrs[-1], OP_BEFORE) for blocknode in func.endpoints]
    real_args = []

    args_uses = {}

    try:
        rd = project.analyses.ReachingDefinitions(subject=func, 
                                                  func_graph=func.graph,
                                                  cc = func.calling_convention,
                                                  observation_points= observation_points,
                                                 )
    except Exception as e:
        l.critical("RD exception during unused_args_analysis")
        for x in func.calling_convention.args:
            if type(x) == angr.calling_conventions.SimRegArg:
                real_args.append(x.reg_name)
        return real_args

    if rd.observed_results != {}:
        if func.calling_convention:
            for func_arg in func.calling_convention.args:
                if type(func_arg) != angr.calling_conventions.SimRegArg:
                    continue
                l.info("Analyzing arg {} of func at {}".format(func_arg.reg_name, hex(func.addr)))
                arg_reg_offest = reg_to_offset(project, func_arg.reg_name) 
                args_uses[func_arg.reg_name] = []
                arg_uses = get_param_uses(rd, arg_reg_offest)
                if arg_uses == None:
                    l.info("Arg {} is never used".format(func_arg.reg_name))
                else:
                    args_uses[func_arg.reg_name] = arg_uses
            return args_uses
    
    return args_uses