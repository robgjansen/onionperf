'''
Created on Oct 1, 2015

@author: rob
'''

import sys, os, logging
from subprocess import Popen, PIPE

def make_path(path):
    p = os.path.abspath(os.path.expanduser(path))
    dirp = os.path.dirname(p)
    if not os.path.exists(dirp):
        os.makedirs(p)
    return p

def find_path(binpath, defaultname):
    # find the path to tor
    if binpath is not None:
        binpath = os.path.abspath(os.path.expanduser(binpath))
    else:
        w = which(defaultname)
        if w is not None:
            binpath = os.path.abspath(os.path.expanduser(w))
        else:
            logging.error("You did not specify a path to a '{0}' binary, and one does not exist in your PATH".format(defaultname))
            return None
    # now make sure the path exists
    if os.path.exists(binpath):
        logging.info("Using '{0}' binary at {1}".format(defaultname, binpath))
    else:
        logging.error("Path to '{0}' binary does not exist: {1}".format(defaultname, binpath))
        return None
    # we found it and it exists
    return binpath

def which(program):
    def is_exe(fpath):
        return os.path.isfile(fpath) and os.access(fpath, os.X_OK)
    fpath, fname = os.path.split(program)
    if fpath:
        if is_exe(program):
            return program
    else:
        for path in os.environ["PATH"].split(os.pathsep):
            exe_file = os.path.join(path, program)
            if is_exe(exe_file):
                return exe_file
    return None

def timestamp_to_seconds(stamp):  # unix timestamp
    return float(stamp)

class DataSource(object):
    def __init__(self, filename, compress=False):
        self.filename = filename
        self.compress = compress
        self.source = None
        self.xzproc = None

    def open(self):
        if self.filename == '-':
            self.source = sys.stdin
        elif self.compress or self.filename.endswith(".xz"):
            cmd = "xz --decompress --stdout {0}".format(self.filename)
            xzproc = Popen(cmd.split(), stdout=PIPE)
            self.source = xzproc.stdout
        else:
            self.source = open(self.filename, 'r')

    def get(self):
        return self.source

    def close(self):
        if self.source is not None: self.source.close()
        if self.xzproc is not None: self.xzproc.wait()

class DataSink(object):
    def __init__(self, filename, compress=False):
        self.filename = filename
        self.compress = compress
        self.sink = None
        self.xzproc = None
        self.ddproc = None
        self.nullf = None

    def open(self):
        if self.filename == '-':
            self.sink = sys.stdout
        elif self.compress or self.filename.endswith(".xz"):
            if not self.filename.endswith(".xz"):
                self.filename += ".xz"
            self.nullf = open("/dev/null", 'a')
            self.xzproc = Popen("xz --threads=3 -".split(), stdin=PIPE, stdout=PIPE)
            self.ddproc = Popen("dd of={0}".format(self.filename).split(), stdin=self.xzproc.stdout, stdout=self.nullf, stderr=self.nullf)
            self.sink = self.xzproc.stdin
        else:
            self.sink = open(self.filename, 'w')

    def get(self):
        return self.sink

    def close(self):
        if self.sink is not None: self.sink.close()
        if self.xzproc is not None: self.xzproc.wait()
        if self.ddproc is not None: self.ddproc.wait()
        if self.nullf is not None: self.nullf.close()
