import angr

######################################
# read
######################################

import logging 
l = logging.getLogger("SimProc")
l.setLevel(logging.DEBUG)

class read(angr.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, fd, dst, length):
        simfd = self.state.posix.get_fd(fd)
        if simfd is None:
            return -1
        fd_int = self.state.solver.eval(fd)
        if fd_int == 3:
            l.info("Overflowing {} bytes into {} from fd {}".format(length, dst, fd))    
        else:
            l.info("Reading {} bytes into {} from fd {}".format(length, dst, fd))
        return simfd.read(dst, length)
