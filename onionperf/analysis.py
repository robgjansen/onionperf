'''
Created on Oct 1, 2015

@author: rob
'''

from abc import ABCMeta, abstractmethod, abstractproperty
from __builtin__ import classmethod

import sys, os, re, json
from multiprocessing import Pool, cpu_count
from signal import signal, SIGINT, SIG_IGN

import util

class Analysis(object):
    '''
    A utility to help analyze onionperf output. Currently, this parses tgen transfer complete messages, and plots the results to a PDF file that is saved in the current directory.
    '''
    __metaclass__ = ABCMeta

    @abstractproperty
    def default_filename(self):
        pass

    @abstractmethod
    def new_parser(self, filepath):
        pass

    def __init__(self):
        self.result = None

    def analyze_file(self, filepath):
        source = util.DataSource(filepath)
        parser = self.new_parser(source)
        parser.parse()
        self.result = parser.merge([])

    @classmethod
    def __analyze_subproc_func(cls, parser):
        signal(SIGINT, SIG_IGN)  # ignore interrupts
        parser.parse()
        return parser

    def analyze_directory(self, search_path, search_expressions, num_subprocs=1):
        logfilepaths = Analysis.__find_file_paths(search_path, search_expressions)
        print >> sys.stderr, "processing input from {0} files...".format(len(logfilepaths))

        if num_subprocs <= 0: num_subprocs = cpu_count()
        pool = Pool(num_subprocs)
        parsers = [self.new_parser(util.DataSource(filepath)) for filepath in logfilepaths]
        try:
            mr = pool.map_async(Analysis.__analyze_subproc_func, parsers)
            pool.close()
            while not mr.ready(): mr.wait(1)
            parsers = mr.get()
        except KeyboardInterrupt:
            print >> sys.stderr, "interrupted, terminating process pool"
            pool.terminate()
            pool.join()
            sys.exit()

        if parsers is not None and len(parsers) > 0:
            parser = parsers.pop()
            self.result = parser.merge(parsers)

    @classmethod
    def __find_file_paths(cls, searchpath, patterns):
        paths = []
        if searchpath.endswith("/-"): paths.append("-")
        else:
            for root, dirs, files in os.walk(searchpath):
                for name in files:
                    found = False
                    fpath = os.path.join(root, name)
                    fbase = os.path.basename(fpath)
                    for pattern in patterns:
                        if re.search(pattern, fbase): found = True
                    if found: paths.append(fpath)
        return paths

    def dump_to_file(self, filename, output_prefix=os.getcwd(), compress=True):
        if self.result == None:
            print >> sys.stderr, "we have no analysis results to dump!"
            return

        print >> sys.stderr, "dumping stats in {0}".format(output_prefix)

        if not os.path.exists(output_prefix): os.makedirs(output_prefix)
        filepath = "{0}/{1}".format(output_prefix, filename)

        output = util.DataSink(filepath, compress=compress)
        output.open()
        json.dump(self.result, output.get(), sort_keys=True, separators=(',', ': '), indent=2)
        output.close()

        print >> sys.stderr, "all done dumping stats to {0}".format(filepath)

    @classmethod
    def from_file(cls, input_prefix=os.getcwd(), filename=None):
        analysis_instance = cls()

        if filename is None:
            filename = analysis_instance.default_filename
        logpath = os.path.abspath(os.path.expanduser("{0}/{1}".format(input_prefix, filename)))

        if not os.path.exists(logpath):
            print >> sys.stderr, "unable to load analysis results from log file at '{0}'".format(logpath)
            if not logpath.endswith(".xz"):
                logpath += ".xz"
                print >> sys.stderr, "trying '{0}'".format(logpath)
                if not os.path.exists(logpath):
                    print >> sys.stderr, "unable to load analysis results from log file at '{0}'".format(logpath)
                    return None

        s = util.DataSource(logpath)
        s.open()
        analysis_instance.result = json.load(s.get())
        s.close()
        return analysis_instance
        # data = prune_data(data, skiptime, rskiptime)
        # tgendata.append((data['nodes'], label, lfcycle.next()))

class TGenAnalysis(Analysis):

    @property
    def default_filename(self):
        return "stats.tgen.json"

    def new_parser(self, source):
        return TGenParser(source)

class TorAnalysis(Analysis):

    @property
    def default_filename(self):
        return "stats.tor.json"

    def new_parser(self, source):
        return TorParser(source)

class Parser(object):
    __metaclass__ = ABCMeta

    @abstractmethod
    def parse(self, source):
        pass

    @abstractmethod
    def merge(self, parsers):
        pass

class TGenParser(Parser):

    def __init__(self, source):
        self.source = source
        self.data = {'firstbyte':{}, 'lastbyte':{}, 'errors':{}}
        self.parsed_name = None
        self.num_successes = 0
        self.num_errors = 0

    def parse(self):
        self.source.open()
        for line in self.source.get():
            if self.parsed_name is None and re.search("Initializing traffic generator on host", line) is not None:
                self.parsed_name = line.strip().split()[11]
            elif re.search("transfer-complete", line) is not None or re.search("transfer-error", line) is not None:
                parts = line.strip().split()
                if len(parts) < 26: continue
                sim_seconds = util.timestamp_to_seconds(parts[2])
                second = int(sim_seconds)

                ioparts = parts[13].split('=')
                iodirection = ioparts[0]
                if 'read' not in iodirection: return None  # this is a server, do we want its stats?
                bytes = int(ioparts[1].split('/')[0])

                if 'transfer-complete' in parts[6]:
                    self.num_successes += 1
                    cmdtime = int(parts[21].split('=')[1]) / 1000.0
                    rsptime = int(parts[22].split('=')[1]) / 1000.0
                    fbtime = int(parts[23].split('=')[1]) / 1000.0
                    lbtime = int(parts[24].split('=')[1]) / 1000.0
                    chktime = int(parts[25].split('=')[1]) / 1000.0

                    if bytes not in self.data['firstbyte']: self.data['firstbyte'][bytes] = {}
                    if second not in self.data['firstbyte'][bytes]: self.data['firstbyte'][bytes][second] = []
                    self.data['firstbyte'][bytes][second].append(fbtime - cmdtime)

                    if bytes not in self.data['lastbyte']: self.data['lastbyte'][bytes] = {}
                    if second not in self.data['lastbyte'][bytes]: self.data['lastbyte'][bytes][second] = []
                    self.data['lastbyte'][bytes][second].append(lbtime - cmdtime)

                elif 'transfer-error' in parts[6]:
                    self.num_errors += 1
                    code = parts[10].strip('()').split('-')[7].split('=')[1]
                    if code not in self.data['errors']: self.data['errors'][code] = {}
                    if second not in self.data['errors'][code]: self.data['errors'][code][second] = []
                    self.data['errors'][code][second].append(bytes)
        self.source.close()

    def merge(self, parsers):
        d = {'nodes':{}}
        name_count, noname_count, success_count, error_count = 0, 0, 0, 0

        parsers.append(self)
        print >> sys.stderr, "merging {0} parsed results now...".format(len(parsers))

        for parser in parsers:
            if parser is None:
                continue
            if parser.parsed_name is None:
                noname_count += 1
                continue
            name_count += 1
            d['nodes'][parser.parsed_name] = parser.data
            success_count += parser.num_successes
            error_count += parser.num_errors

        print >> sys.stderr, "done merging results: {0} total successes, {1} total errors, {2} files with names, {3} files without names".format(success_count, error_count, name_count, noname_count)
        return d

class TorParser(Parser):

    def __init__(self, source):
        self.source = source
        self.data = {'bytes_read':{}, 'bytes_written':{}}
        self.name = None
        self.boot_succeeded = False
        self.total_read = 0
        self.total_write = 0

    def parse(self):
        self.source.open()
        for line in self.source.get():
            if self.name is None and re.search("Starting torctl program on host", line) is not None:
                parts = line.strip().split()
                if len(parts) < 11: continue
                self.name = parts[10]
            elif not self.boot_succeeded and re.search("Bootstrapped 100", line) is not None:
                self.boot_succeeded = True
            elif self.boot_succeeded and re.search("\s650\sBW\s", line) is not None:
                parts = line.strip().split()
                if len(parts) < 11: continue
                if 'Outbound' in line: print line
                second = int(float(parts[2]))
                bwr = int(parts[9])
                bww = int(parts[10])

                if second not in self.data['bytes_read']: self.data['bytes_read'][second] = 0
                self.data['bytes_read'][second] += bwr
                self.total_read += bwr
                if second not in self.data['bytes_written']: self.data['bytes_written'][second] = 0
                self.data['bytes_written'][second] += bww
                self.total_write += bww
        self.source.close()

        # XXX this is a hack to try to get the name
        # a better approach would be get the Tor nickname, from ctl port?
        if self.name is None: self.name = os.path.dirname(self.source.filename)

    def merge(self, parsers):
        d = {'nodes':{}}
        name_count, noname_count, success_count, error_count, total_read, total_write = 0, 0, 0, 0, 0, 0

        parsers.append(self)
        print >> sys.stderr, "merging {0} parsed results now...".format(len(parsers))

        for parser in parsers:
            if parser is None:
                continue

            if parser.name is not None:
                name_count += 1
            else:
                noname_count += 1
                continue

            if parser.boot_succeeded:
                success_count += 1
            else:
                error_count += 1
                print >> sys.stderr, "warning: tor running on host '{0}' did not fully bootstrap".format(parser.name)
                continue

            d['nodes'][parser.name] = parser.data
            total_read += parser.total_read
            total_write += parser.total_write

        print >> sys.stderr, "done merging results: {0} boot success count, {1} boot error count, {2} files with names, {3} files without names, {4} total bytes read, {5} total bytes written".format(success_count, error_count, name_count, noname_count, total_read, total_write)
        return d

'''
from stem.response import ControlMessage, convert

msg = ControlMessage.from_str("650 BW 1532 2656\r\n")
convert('EVENT', msg)
print msg
'''
