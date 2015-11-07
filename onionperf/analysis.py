'''
Created on Oct 1, 2015

@author: rob
'''

from abc import ABCMeta, abstractmethod, abstractproperty
from __builtin__ import classmethod

import sys, os, re, json, datetime
from multiprocessing import Pool, cpu_count
from signal import signal, SIGINT, SIG_IGN

from stem.response import ControlMessage, convert
import util
from socket import gethostname

def analyze_subproc_func(parser):
    signal(SIGINT, SIG_IGN)  # ignore interrupts
    parser.parse()
    return parser

class Analysis(object):
    '''
    A utility to help analyze onionperf output. Currently, this parses tgen transfer complete messages, and plots the results to a PDF file that is saved in the current directory.
    '''
    __metaclass__ = ABCMeta

    @abstractproperty
    def default_filename(self):
        pass

    @abstractmethod
    def new_parser(self, sources):
        pass

    def __init__(self):
        self.result = None

    # this is meant to be used in cases where a single 'parser' instance should process
    # multiple files because state needs to be kept across all of the files
    # for example, it can be used when a large log file was split to several smaller files
    # the parser will process them in sequence
    def analyze_files(self, filepaths_list):
        sources = [util.DataSource(filepath) for filepath in filepaths_list]
        parser = self.new_parser(sources)
        parser.parse()
        self.result = parser.merge([])

    def analyze_file(self, filepath):
        self.analyze_files([filepath])

    @classmethod
    def __analyze_subproc_func(cls, parser):
        signal(SIGINT, SIG_IGN)  # ignore interrupts
        parser.parse()
        return parser

    # this is meant to be used in cases where each matching file in the directory should be processed
    # by separate parsers, because each of those files do not need to share parser state
    # this is useful when different nodes create their own log files, and we want to process them
    # all in parallel
    def analyze_directory(self, search_path, search_expressions, num_subprocs=1):
        logfilepaths = Analysis.__find_file_paths(search_path, search_expressions)
        print >> sys.stderr, "processing input from {0} files...".format(len(logfilepaths))

        if num_subprocs <= 0: num_subprocs = cpu_count()
        pool = Pool(num_subprocs)
        parsers = [self.new_parser([util.DataSource(filepath)]) for filepath in logfilepaths]
        try:
            mr = pool.map_async(analyze_subproc_func, parsers)
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

        output = util.FileWritable(filepath, do_compress=compress)
        output.open()
        json.dump(self.result, output.file, sort_keys=True, separators=(',', ': '), indent=2)
        output.close()

        print >> sys.stderr, "all done dumping stats to {0}".format(output.filename)

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
        analysis_instance.result = json.load(s.get_file_handle())
        s.close()
        return analysis_instance
        # data = prune_data(data, skiptime, rskiptime)
        # tgendata.append((data['nodes'], label, lfcycle.next()))

class TGenAnalysis(Analysis):

    @property
    def default_filename(self):
        return "stats.tgen.json"

    def new_parser(self, sources):
        return TGenParser(sources)

class TorAnalysis(Analysis):

    @property
    def default_filename(self):
        return "stats.tor.json"

    def new_parser(self, sources):
        return TorParser(sources)

class Parser(object):
    __metaclass__ = ABCMeta

    @abstractmethod
    def parse(self, sources):
        pass

    @abstractmethod
    def merge(self, parsers):
        pass

class TGenParser(Parser):

    def __init__(self, sources):
        self.sources = sources
        self.data = {'firstbyte':{}, 'lastbyte':{}, 'errors':{}}
        self.parsed_name = None
        self.num_successes = 0
        self.num_errors = 0

    def parse(self):
        for s in self.sources:
            s.open()
            for line in s:
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
                        transfer_str = parts[10]
                        splitchar = ',' if ',' in transfer_str else '-'
                        code = transfer_str.strip('()').split(splitchar)[7].split('=')[1]
                        if code not in self.data['errors']: self.data['errors'][code] = {}
                        if second not in self.data['errors'][code]: self.data['errors'][code][second] = []
                        self.data['errors'][code][second].append(bytes)
            s.close()

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

    def __init__(self, sources):
        self.sources = sources
        self.data = {'bytes_read':{}, 'bytes_written':{}}
        self.name = None
        self.boot_succeeded = False
        self.total_read = 0
        self.total_write = 0

    def parse(self):
        for s in self.sources:
            # XXX this is a hack to try to get the name
            # a better approach would be get the Tor nickname, from ctl port?
            if self.name is None: self.name = os.path.basename(os.path.dirname(s.filename))
            s.open()
            for line in s:
                if not self.boot_succeeded:
                    if re.search("Starting\storctl\sprogram\son\shost", line) is not None:
                        parts = line.strip().split()
                        if len(parts) < 11: continue
                        self.name = parts[10]
                    if re.search("Bootstrapped\s100", line) is not None:
                        self.boot_succeeded = True
                elif re.search("\s650\sBW\s", line) is not None:
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
            s.close()
        self.source.open()

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

class TorPerfEntry(object):
    def __init__(self, tid, local_proxy_str, remote_server_str, local_hostname, remote_hostname, filesize):
        self.id = tid
        self.local_proxy_str = local_proxy_str
        self.remote_server_str = remote_server_str
        self.local_hostname = local_hostname
        self.remote_hostname = remote_hostname
        self.data = {}
        # https://collector.torproject.org/#type-torperf
        # TODO make this an enum
        for key in ['LAUNCH', 'START', 'SOCKET', 'CONNECT', 'NEGOTIATE', \
                  'REQUEST', 'RESPONSE', 'DATAREQUEST', 'DATARESPONSE', \
                  'DATAPERC10', 'DATAPERC20', 'DATAPERC30', 'DATAPERC40', 'DATAPERC50', \
                  'DATAPERC60', 'DATAPERC70', 'DATAPERC80', 'DATAPERC90', 'DATACOMPLETE', \
                  'SOURCE', 'FILESIZE', 'READBYTES', 'WRITEBYTES', \
                  'PATH', 'BUILDTIMES', 'QUANTILE', 'TIMEOUT', \
                  'CIRC_ID', 'USED_AT', 'USED_BY', 'DIDTIMEOUT']:
            self.data[key] = None  # initialize known keys
        self.set('FILESIZE', filesize)
        self.last_bytes = 0

    def update_progress(self, time, numbytes):
        if numbytes > self.last_bytes:
            self.last_bytes = numbytes
            frac = float(self.last_bytes) / float(self.data['FILESIZE'])
            perc = frac * 100.0
            for i in [10, 20, 30, 40, 50, 60, 70, 80, 90]:
                k = 'DATAPERC{0}'.format(i)
                if int(perc) >= i and self.data[k] is None:
                    self.set(k, "{0:.2f}".format(time))

    def set(self, key, value):
        if key in self.data:
            self.data[key] = value

    def to_torperf_string(self):
        self.data['ENDPOINT-LOCAL'] = self.local_proxy_str
        self.data['ENDPOINT-REMOTE'] = self.remote_server_str
        self.data['HOSTNAME-LOCAL'] = self.local_hostname
        self.data['HOSTNAME-REMOTE'] = self.remote_hostname
        return ' '.join("{0}={1}".format(k, self.data[k]) for k in sorted(self.data.keys()) if self.data[k] is not None).strip()

    def assert_monotonic_order(self):
        keys_in_order = ['START', 'SOCKET', 'CONNECT', 'NEGOTIATE', 'REQUEST', 'RESPONSE', \
             'DATAREQUEST', 'DATARESPONSE', 'DATAPERC10', 'DATAPERC20', 'DATAPERC30', 'DATAPERC40', \
             'DATAPERC50', 'DATAPERC60', 'DATAPERC70', 'DATAPERC80', 'DATAPERC90', 'DATACOMPLETE']
        prev_ts = 0.0
        for k in keys_in_order:
            ts = float(self.data[k])
            assert ts >= prev_ts, "monotonic time error for entry {0} key {1}: {2} << {3}".format(self.id, k, ts, prev_ts)
            prev_ts = ts

class TorPerfParser(Parser):

    def __init__(self, sources, name=None):
        self.sources = sources
        self.name = name
        self.boot_succeeded = False
        self.transfers = {}
        self.sizes = {}
        self.first_complete_dt = datetime.datetime.today()

    def parse(self):
        for s in self.sources:
            s.open()
            for line in s:
                try:
                    if self.name is None and re.search("Initializing traffic generator on host", line) is not None:
                        self.name = line.strip().split()[11].split('.')[0]

                    if not self.boot_succeeded:
                        if re.search("Bootstrapped\s100", line) is not None:
                            self.boot_succeeded = True

                    # parse out torperf stats
                    is_new, is_status, is_complete, is_torctlmsg = False, False, False, False
                    if re.search("state\sCOMMAND\sto\sstate\sRESPONSE", line) is not None: is_new = True
                    elif re.search("transfer-status", line) is not None: is_status = True
                    elif re.search("transfer-complete", line) is not None: is_complete = True
                    elif re.search("\s650\s", line) is not None: is_torctlmsg = True

                    if is_new:
                        # another run of tgen starts the id over counting up from 1
                        # if a prev transfer with the same id did not complete, we can be sure it never will
                        transfer_str = line.strip().split()[7]
                        splitchar = ',' if ',' in transfer_str else '-'
                        tid = int(transfer_str.strip('()').split(splitchar)[0])
                        if tid in self.transfers: self.transfers.pop(tid)

                    if is_status or is_complete:
                        parts = line.strip().split()
                        unix_ts, transport_str, transfer_str, status = float(parts[2]), parts[8], parts[10], parts[13]
                        downloaded, filesize = [int(i) for i in status.split('=')[1].split('/')]

                        transfer_parts = transfer_str.strip('()').split(',' if ',' in transfer_str else '-')
                        tid = int(transfer_parts[0])

                        # create if needed
                        if tid not in self.transfers:
                            transport_parts = transport_str.strip('()').split(',' if ',' in transport_str else '-')
                            endpoint_local, endpoint_remote = transport_parts[2], transport_parts[3]
                            hostname_local, hostname_remote = transfer_parts[1], transfer_parts[4]
                            self.transfers[tid] = TorPerfEntry(tid, endpoint_local, endpoint_remote, hostname_local, hostname_remote, filesize)

                        # stats to add during download
                        self.transfers[tid].update_progress(unix_ts, downloaded)

                        # stats to add when finished
                        if is_complete:
                            total_read, total_write = int(parts[11].split('=')[1]), int(parts[12].split('=')[1])
                            self.transfers[tid].set('READBYTES', total_read)
                            self.transfers[tid].set('WRITEBYTES', total_write)

                            def keyval_to_secs(keyval): return float(int(keyval.split('=')[1])) / 1000.0
                            def ts_to_str(ts): return"{0:.02f}".format(ts)

                            s_to_cksum = keyval_to_secs(parts[25])
                            start_ts = unix_ts - s_to_cksum

                            self.transfers[tid].set('START', ts_to_str(start_ts))
                            self.transfers[tid].set('SOCKET', ts_to_str(start_ts + keyval_to_secs(parts[15])))
                            self.transfers[tid].set('CONNECT', ts_to_str(start_ts + keyval_to_secs(parts[16])))
                            self.transfers[tid].set('NEGOTIATE', ts_to_str(start_ts + keyval_to_secs(parts[18])))
                            self.transfers[tid].set('REQUEST', ts_to_str(start_ts + keyval_to_secs(parts[19])))
                            self.transfers[tid].set('RESPONSE', ts_to_str(start_ts + keyval_to_secs(parts[20])))
                            self.transfers[tid].set('DATAREQUEST', ts_to_str(start_ts + keyval_to_secs(parts[21])))
                            self.transfers[tid].set('DATARESPONSE', ts_to_str(start_ts + keyval_to_secs(parts[22])))
                            self.transfers[tid].set('DATACOMPLETE', ts_to_str(unix_ts))

                            if len(self.sizes) == 0: self.first_complete_dt = datetime.datetime.fromtimestamp(unix_ts)
                            if filesize not in self.sizes: self.sizes[filesize] = []

                            # make sure the timestamps are in order, if not, we catch the error
                            # and wont add this entry to the completed downloads
                            self.transfers[tid].assert_monotonic_order()
                            self.sizes[filesize].append(self.transfers[tid])
                            self.transfers.pop(tid)

                    if is_torctlmsg:
                        # parse with stem
                        raw_event_str = line[line.index("650 "):]
                        # msg = ControlMessage.from_str(raw_event_str)
                        # convert('EVENT', msg)

                        # do something with the new ControlMessage object
                except:
                    continue  # probably a line overwrite error
            s.close()

    def merge(self, parsers):
        # merging multiple parsers is not supported for torperf
        return None

    def export_torperf_files(self, output_prefix=os.getcwd(), compress=True):
        if not os.path.exists(output_prefix): os.makedirs(output_prefix)

        if self.name is None: self.name = gethostname().split('.')[0]

        d = self.first_complete_dt
        datestr = "{0}-{1}-{2}".format(d.year, d.month, d.day) if d is not None else "0000-00-00"

        for size_bytes in self.sizes:
            l = self.sizes[size_bytes]
            filepath = "{0}/{1}-{2}-{3}.tpf".format(output_prefix, self.name, size_bytes, datestr)
            should_append = os.path.exists(filepath) and not compress
            output = util.FileWritable(filepath, do_compress=compress)
            output.open()
            if not should_append: output.write("@type torperf 1.0\r\n")
            for entry in l:
                entry.set('SOURCE', self.name)
                output.write("{0}\r\n".format(entry.to_torperf_string()))
            output.close()

