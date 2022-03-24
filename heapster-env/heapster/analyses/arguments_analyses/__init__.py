from .unused_args_analysis import *
from .malloc_args_analysis import *
from .arg_values_analysis import *
from .free_args_analysis import *

'''
Wrapper class to store information regarding 
an argument of a function
'''
class ArgInfo():
    def __init__(self, name, angr_decompiler_type=None, is_size=False, is_ptr_to_free=False, values=None):
        self.name = name
        self.angr_decompiler_type = angr_decompiler_type
        self.is_size = is_size
        self.values = values
        self.is_ptr_to_free = is_ptr_to_free
    
    def __repr__(self):
        return "ArgInfo | name: {} | angr_decompiler_type: {} | is_size: {} | is_ptr_to_free {}| values: {}".format(self.name, 
                                                                self.angr_decompiler_type, 
                                                                self.is_size, 
                                                                self.is_ptr_to_free,
                                                                self.values)
