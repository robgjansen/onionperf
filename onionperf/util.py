'''
Created on Oct 1, 2015

@author: rob
'''

import sys, os, logging
from subprocess import Popen, PIPE
from cStringIO import StringIO
from abc import ABCMeta, abstractmethod
import shutil, time

def make_path(path):
    p = os.path.abspath(os.path.expanduser(path))
    if not os.path.exists(p):
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

class Writable(object):
    __metaclass__ = ABCMeta

    @abstractmethod
    def write(self, msg):
        pass

    @abstractmethod
    def close(self):
        pass

class FileWritable(Writable):

    def __init__(self, filename, do_compress=False):
        self.filename = filename
        self.do_compress = do_compress
        self.file = None
        self.xzproc = None
        self.ddproc = None
        self.nullf = None

        if self.filename == '-':
            self.file = sys.stdout
        elif self.do_compress or self.filename.endswith(".xz"):
            self.do_compress = True
            if not self.filename.endswith(".xz"):
                self.filename += ".xz"

    def write(self, msg):
        if self.file is None:
            self.file = self.open()
        if self.file is not None:
            self.file.write(msg)

    def open(self):
        if self.compress:
            self.nullf = open("/dev/null", 'a')
            self.xzproc = Popen("xz --threads=3 -".split(), stdin=PIPE, stdout=PIPE)
            self.ddproc = Popen("dd of={0}".format(self.filename).split(), stdin=self.xzproc.stdout, stdout=self.nullf, stderr=self.nullf)
            self.file = self.xzproc.stdin
        else:
            self.file = open(self.filename, 'w')

    def close(self):
        if self.file is not None:
            self.file.close()

class RotateFileWritable(FileWritable):

    def rotate_file(self):
        base = os.path.basename(self.filename)
        base_noext = os.path.splitext(os.path.splitext(base)[0])[0]
        ts = time.strftime("%Y-%m-%d_%H:%M:%S")
        new_base = base.replace(base_noext, "{0}_{1}".format(base_noext, ts))
        new_filename = self.filename.replace(base, new_base)
        shutil.copy2(self.filename, new_filename)
        self.file.truncate(0)
        return new_filename

class MemoryWritable(Writable):

    def __init__(self):
        self.str_buffer = StringIO()

    def write(self, msg):
        self.str_buffer.write()

    def readline(self):
        return self.str_buffer.readline()

    def close(self):
        self.str_buffer.close()
