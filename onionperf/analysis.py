'''
Created on Oct 1, 2015

@author: rob
'''

from abc import ABCMeta, abstractmethod

import sys, os, re, json, datetime, logging
from multiprocessing import Pool, cpu_count
from signal import signal, SIGINT, SIG_IGN

import stem, stem.response, stem.response.events
from stem.response import ControlMessage, convert
import util
from socket import gethostname

class Analysis(object):

    def __init__(self, nickname=None):
        self.nickname = nickname
        self.hostname = gethostname().split('.')[0]
        self.json_db = {'type':'onionperf', 'version':1.0, 'data':{}}
        self.tgen_filepaths = []
        self.torctl_filepaths = []

    def add_tgen_file(self, filepath):
        self.tgen_filepaths.append(filepath)

    def add_torctl_file(self, filepath):
        self.torctl_filepaths.append(filepath)

    def analyze(self, do_simple=True):
        for (filepaths, parser) in [(self.tgen_filepaths, TGenParser()), (self.torctl_filepaths, TorCtlParser())]:
            if len(filepaths) > 0:
                for filepath in filepaths:
                    logging.info("parsing log file at {0}".format(filepath))
                    parser.parse(util.DataSource(filepath), do_simple=do_simple)
                parsed_name = parser.get_name()
                n = self.nickname
                if n is None:
                    n = parsed_name if parsed_name is not None else self.hostname
                self.json_db['data'].setdefault(n, {}).setdefault('tgen', parser.get_data())

    def merge(self, analysis):
        for nickname in analysis.json_db['data']:
            if nickname in self.json_db['data']:
                raise Exception("Merge does not yet support multiple Analysis objects from the same node \
                (add multiple files from the same node to the same Analysis object before calling analyze instead)")
            else:
                self.json_db['data'][nickname] = analysis.json_db['data'][nickname]

    def save(self, filename="onionperf.analysis.json.xz", output_prefix=os.getcwd(), do_compress=True, version=1.0):
        filepath = os.path.abspath(os.path.expanduser("{0}/{1}".format(output_prefix, filename)))
        if not os.path.exists(output_prefix):
            os.makedirs(output_prefix)

        logging.info("saving analysis results to {0}".format(filepath))

        outf = util.FileWritable(filepath, do_compress=do_compress)
        json.dump(self.json_db, outf, sort_keys=True, separators=(',', ': '), indent=2)
        outf.close()

        logging.info("done!")

    @classmethod
    def load(cls, filename="onionperf.analysis.json.xz", input_prefix=os.getcwd(), version=1.0):
        filepath = os.path.abspath(os.path.expanduser("{0}/{1}".format(input_prefix, filename)))
        if not os.path.exists(filepath):
            logging.warning("file does not exist at '{0}'".format(filepath))
            return None

        logging.info("loading analysis results from {0}".format(filepath))

        inf = util.DataSource(filepath)
        inf.open()
        db = json.load(inf.get_file_handle())
        inf.close()

        logging.info("done!")

        if 'type' not in db or 'version' not in db:
            logging.warning("'type' or 'version' not present in database")
            return None
        elif db['type'] != 'onionperf' or db['version'] != 1.0:
            logging.warning("type or version not supported (type={0}, version={1})".format(db['type'], db['version']))
            return None
        else:
            analysis_instance = cls()
            analysis_instance.json_db = db
            return analysis_instance

    def export_torperf_version_1_0(self, output_prefix=os.getcwd(), datetimestamp=None, do_compress=False):
        # export file in `@type torperf 1.0` format: https://collector.torproject.org/#type-torperf
        if not os.path.exists(output_prefix):
            os.makedirs(output_prefix)

        if datetimestamp is None:
            datetimestamp = datetime.datetime.utcnow()
        datestr = "{0:04d}-{1:02d}-{2:02d}".format(datetimestamp.year, datetimestamp.month, datetimestamp.day)

        for nickname in self.json_db['data']:
            if 'tgen' not in self.json_db['data'][nickname] or 'transfers' not in self.json_db['data'][nickname]['tgen']:
                continue

            xfers_by_filesize = {}
            for xfer_db in self.json_db['data'][nickname]['tgen']['transfers'].values():
                xfers_by_filesize.setdefault(xfer_db['filesize_bytes'], []).append(xfer_db)

            for filesize in xfers_by_filesize:
                filepath = "{0}/{1}-{2}-{3}.tpf{4}".format(output_prefix, nickname, filesize, datestr, '.xz' if do_compress else '')

                logging.info("saving analysis results to {0}".format(filepath))

                # if the file exists, try to append to it
                # this needs to be checked before opening the file
                should_append = os.path.exists(filepath) and not do_compress

                output = util.FileWritable(filepath, do_compress=do_compress)
                output.open()

                if not should_append:
                    output.write("@type torperf 1.0\r\n")

                for xfer_db in xfers_by_filesize[filesize]:
                    d = {}

                    d['SOURCE'] = nickname
                    d['ENDPOINTLOCAL'] = xfer_db['endpoint_local']
                    d['ENDPOINTPROXY'] = xfer_db['endpoint_proxy']
                    d['ENDPOINTREMOTE'] = xfer_db['endpoint_remote']
                    d['HOSTNAMELOCAL'] = xfer_db['hostname_local']
                    d['HOSTNAMEREMOTE'] = xfer_db['hostname_remote']

                    d['FILESIZE'] = xfer_db['filesize_bytes']
                    d['READBYTES'] = xfer_db['total_bytes_read']
                    d['WRITEBYTES'] = xfer_db['total_bytes_write']

                    def ts_to_str(ts): return"{0:.02f}".format(ts)

                    d['START'] = ts_to_str(xfer_db['unix_ts_start'])
                    d['SOCKET'] = ts_to_str(xfer_db['unix_ts_start'] + xfer_db['elapsed_seconds']['socket_create'])
                    d['CONNECT'] = ts_to_str(xfer_db['unix_ts_start'] + xfer_db['elapsed_seconds']['socket_connect'])
                    d['NEGOTIATE'] = ts_to_str(xfer_db['unix_ts_start'] + xfer_db['elapsed_seconds']['proxy_choice'])
                    d['REQUEST'] = ts_to_str(xfer_db['unix_ts_start'] + xfer_db['elapsed_seconds']['proxy_request'])
                    d['RESPONSE'] = ts_to_str(xfer_db['unix_ts_start'] + xfer_db['elapsed_seconds']['proxy_response'])
                    d['DATAREQUEST'] = ts_to_str(xfer_db['unix_ts_start'] + xfer_db['elapsed_seconds']['command'])
                    d['DATARESPONSE'] = ts_to_str(xfer_db['unix_ts_start'] + xfer_db['elapsed_seconds']['response'])

                    # set DATAPERC[10,20,...,90]
                    for decile in sorted(xfer_db['elapsed_seconds']['payload'].keys()):
                        if xfer_db['elapsed_seconds']['payload'][decile] is not None:
                            d['DATAPERC{0}'.format(int(decile * 100))] = ts_to_str(xfer_db['unix_ts_start'] + xfer_db['elapsed_seconds']['payload'][decile])

                    d['DATACOMPLETE'] = ts_to_str(xfer_db['unix_ts_start'] + xfer_db['elapsed_seconds']['last_byte'])

                    d['LAUNCH'] = None
                    d['PATH'] = None
                    d['BUILDTIMES'] = None
                    d['QUANTILE'] = None
                    d['TIMEOUT'] = None
                    d['CIRC_ID'] = None
                    d['USED_AT'] = None
                    d['USED_BY'] = None
                    d['DIDTIMEOUT'] = None

                    output_str = ' '.join("{0}={1}".format(k, d[k]) for k in sorted(d.keys()) if d[k] is not None).strip()
                    output.write("{0}\r\n".format(output_str))

                output.close()
                logging.info("done!")

def subproc_analyze_func(analysis_args):
    signal(SIGINT, SIG_IGN)  # ignore interrupts
    a = analysis_args[0]
    do_simple = analysis_args[1]
    a.analyze(do_simple=do_simple)
    return a

class ParallelAnalysis(Analysis):

    def analyze(self, search_path, do_simple=True, nickname=None, tgen_search_expressions=["tgen.*\.log"],
                torctl_search_expressions=["torctl.*\.log"], num_subprocs=cpu_count()):

        pathpairs = util.find_file_paths_pairs(search_path, tgen_search_expressions, torctl_search_expressions)
        logging.info("processing input from {0} nodes...".format(len(pathpairs)))

        analysis_jobs = []
        for (tgen_filepaths, torctl_filepaths) in pathpairs:
            a = Analysis()
            for tgen_filepath in tgen_filepaths:
                a.add_tgen_file(tgen_filepath)
            for torctl_filepath in torctl_filepaths:
                a.add_torctl_file(torctl_filepath)
            analysis_args = [a, do_simple]
            analysis_jobs.append(analysis_args)

        analyses = None
        pool = Pool(num_subprocs if num_subprocs > 0 else cpu_count())
        try:
            mr = pool.map_async(subproc_analyze_func, analysis_jobs)
            pool.close()
            while not mr.ready(): mr.wait(1)
            analyses = mr.get()
        except KeyboardInterrupt:
            logging.info("interrupted, terminating process pool")
            pool.terminate()
            pool.join()
            sys.exit()

        logging.info("merging {0} analysis results now...".format(len(analyses)))
        while analyses is not None and len(analyses) > 0:
            self.merge(analyses.pop())
        logging.info("done merging results: {0} total nicknames present in json db".format(len(self.json_db['data'])))

class TransferStatusEvent(object):

    def __init__(self, line):
        self.is_success = False
        self.is_error = False
        self.is_complete = False

        parts = line.strip().split()
        self.unix_ts = util.timestamp_to_seconds(parts[2])

        transport_parts = parts[8].split(',' if ',' in parts[8] else '-')
        self.endpoint_local = transport_parts[2]
        self.endpoint_proxy = transport_parts[3]
        self.endpoint_remote = transport_parts[4]

        transfer_parts = parts[10].split(',' if ',' in parts[10] else '-')
        transfer_num = int(transfer_parts[0])
        self.hostname_local = transfer_parts[1]
        self.method = transfer_parts[2]  # 'GET' or 'PUT'
        self.filesize_bytes = int(transfer_parts[3])
        self.hostname_remote = transfer_parts[4]
        self.error_code = transfer_parts[7].split('=')[1]

        # for id, combine the time with the transfer num; this is unique for each node,
        # as long as the node was running tgen without restarting for 100 seconds or longer
        # #self.transfer_id = "{0}-{1}".format(round(self.unix_ts, -2), transfer_num)
        self.transfer_id = transfer_num

        self.total_bytes_read = int(parts[11].split('=')[1])
        self.total_bytes_write = int(parts[12].split('=')[1])

        # the commander is the side that sent the command,
        # i.e., the side that is driving the download, i.e., the client side
        progress_parts = parts[13].split('=')
        self.is_commander = (self.method == 'GET' and 'read' in progress_parts[0]) or \
                            (self.method == 'PUT' and 'write' in progress_parts[0])
        self.payload_bytes_status = int(progress_parts[1].split('/')[0])

        self.unconsumed_parts = None if len(parts) < 16 else parts[15:]
        self.elapsed_seconds = {}

class TransferCompleteEvent(TransferStatusEvent):
    def __init__(self, line):
        super(TransferCompleteEvent, self).__init__(line)
        self.is_complete = True

        def keyval_to_secs(keyval): return float(int(keyval.split('=')[1])) / 1000.0

        prev_elapsed = 0.0
        # match up self.unconsumed_parts[0:11] with the events in the transfer_steps enum
        for k in ['socket_create', 'socket_connect', 'proxy_init', 'proxy_choice', 'proxy_request',
                  'proxy_response', 'command', 'response', 'first_byte', 'last_byte', 'checksum']:
            # parse out the elapsed time value
            self.elapsed_seconds.setdefault(k, keyval_to_secs(self.unconsumed_parts[len(self.elapsed_seconds)]))

            # make sure the elapsed times are monotonically increasing
            next_elapsed = self.elapsed_seconds[k]
            if next_elapsed < prev_elapsed:
                logging.warning("monotonic time error for entry {0} key {1}: next {2} is not >= prev {3}".format(self.id, k, next_elapsed, prev_elapsed))
                return None
            prev_elapsed = next_elapsed

        self.unix_ts_end = self.unix_ts
        self.unix_ts_start = self.unix_ts - self.elapsed_seconds['checksum']
        del(self.unconsumed_parts)

class TransferSuccessEvent(TransferCompleteEvent):
    def __init__(self, line):
        super(TransferSuccessEvent, self).__init__(line)
        self.is_success = True

class TransferErrorEvent(TransferCompleteEvent):
    def __init__(self, line):
        super(TransferErrorEvent, self).__init__(line)
        self.is_error = True

class Transfer(object):
    def __init__(self, tid):
        self.id = tid
        self.last_event = None
        self.payload_progress = {decile:None for decile in [0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0]}

    def add_event(self, status_event):
        progress_frac = float(status_event.payload_bytes_status) / float(status_event.filesize_bytes)
        for decile in sorted(self.payload_progress.keys()):
            if progress_frac >= decile and self.payload_progress[decile] is None:
                self.payload_progress[decile] = status_event.unix_ts
        self.last_event = status_event

    def get_data(self):
        e = self.last_event
        if e is None or not e.is_complete:
            return None
        d = e.__dict__
        d['elapsed_seconds']['payload'] = {decile: self.payload_progress[decile] - e.unix_ts_start for decile in self.payload_progress}
        return d

class Parser(object):
    __metaclass__ = ABCMeta
    @abstractmethod
    def parse(self, source, do_simple):
        pass
    @abstractmethod
    def get_data(self):
        pass
    @abstractmethod
    def get_name(self):
        pass

class TGenParser(Parser):

    def __init__(self):
        self.state = {}
        self.transfers = {}
        self.transfers_summary = {'time_to_first_byte':{}, 'time_to_last_byte':{}, 'errors':{}}
        self.name = None

    def __parse_line(self, line, do_simple):
        if self.name is None and re.search("Initializing traffic generator on host", line) is not None:
            self.name = line.strip().split()[11]

        elif not do_simple and re.search("state\sRESPONSE\sto\sstate\sPAYLOAD", line) is not None:
            # another run of tgen starts the id over counting up from 1
            # if a prev transfer with the same id did not complete, we can be sure it never will
            parts = line.strip().split()
            transfer_id = int(parts[7].strip().split(',' if ',' in parts[7] else '-')[0])
            if transfer_id in self.state:
                self.state.pop(transfer_id)

        elif not do_simple and re.search("transfer-status", line) is not None:
            status = TransferStatusEvent(line)
            xfer = self.state.setdefault(status.transfer_id, Transfer(status.transfer_id))
            xfer.add_event(status)

        elif re.search("transfer-complete", line) is not None:
            complete = TransferSuccessEvent(line)

            if not do_simple:
                xfer = self.state.setdefault(complete.transfer_id, Transfer(complete.transfer_id))
                xfer.add_event(complete)
                self.transfers[xfer.id] = xfer.get_data()
                self.state.pop(complete.transfer_id)

            filesize, second = complete.filesize_bytes, int(complete.unix_ts)
            fb_secs = complete.elapsed_seconds['first_byte'] - complete.elapsed_seconds['command']
            lb_secs = complete.elapsed_seconds['last_byte'] - complete.elapsed_seconds['command']

            fb_list = self.transfers_summary['time_to_first_byte'].setdefault(filesize, {}).setdefault(second, [])
            fb_list.append(fb_secs)
            lb_list = self.transfers_summary['time_to_last_byte'].setdefault(filesize, {}).setdefault(second, [])
            lb_list.append(lb_secs)

        elif re.search("transfer-error", line) is not None:
            error = TransferErrorEvent(line)

            if not do_simple:
                xfer = self.state.setdefault(error.transfer_id, Transfer(error.transfer_id))
                xfer.add_event(error)
                self.transfers[xfer.id] = xfer.get_data()
                self.state.pop(error.transfer_id)

            err_code, filesize, second = error.error_code, error.filesize_bytes, int(error.unix_ts)

            err_list = self.transfers_summary['errors'].setdefault(err_code, {}).setdefault(second, [])
            err_list.append(filesize)

        return True

    def parse(self, source, do_simple=True):
        source.open()
        for line in source:
            # ignore line parsing errors
            try:
                if not self.__parse_line(line, do_simple):
                    break
            except:
                logging.warning("TGenParser: skipping line due to parsing error: {0}".format(line))
                raise
                continue
        source.close()

    def get_data(self):
        return {'transfers':self.transfers, 'transfers_summary': self.transfers_summary}

    def get_name(self):
        return self.name

class Stream(object):
    def __init__(self, sid):
        self.id = sid
        self.circ_id = None
        self.events = {}

    def add_event(self, event, circ_id, arrived_at):
        event_str = str(event)
        if event_str not in self.events:
            self.events[event_str] = arrived_at
        if circ_id:
            self.circ_id = circ_id

    def get_event(self, event):
        try:
            return self.events[event]
        except KeyError:
            return None

    def __str__(self):
        return('stream id=%d circ_id=%s %s' % (self.id, self.circ_id,
               ' '.join(['%s=%s' % (event, arrived_at)
               for (event, arrived_at) in self.events.items()])))

class Circuit(object):
    def __init__(self, cid):
        self.id = cid
        self.events = {}

    def add_event(self, event, arrived_at):
        event_str = str(event)
        if event_str not in self.events:
            self.events[event_str] = arrived_at

    def get_event(self, event):
        try:
            return self.events[event]
        except KeyError:
            return None

    def __str__(self):
        return('circuit id=%d %s' % (self.id, ' '.join(['%s=%s' %
               (event, arrived_at) for (event, arrived_at) in
               self.events.items()])))

class TorCtlParser(Parser):

    def __init__(self):
        self.streams = {}
        self.circuits = {}
        self.data = {'bytes_read':{}, 'bytes_written':{}}
        self.name = None
        self.boot_succeeded = False
        self.total_read = 0
        self.total_write = 0

    def __handle_circuit_general(self, event, arrival_dt):
        cid = int(event.id)
        self.circuits.setdefault(cid, Circuit(cid)).add_event(event.state, arrival_dt)

    def __handle_circuit_hs(self, event, arrival_dt):
        cid = int(event.id)
        self.__handle_circuit_general(event, arrival_dt)
        self.circuits.setdefault(cid, Circuit(cid)).add_event(event.hs_state, arrival_dt)

    def __handle_stream(self, event, arrival_dt):
        sid = int(event.id)
        self.streams.setdefault(sid, Stream(sid)).add_event(event.status, event.circ_id, arrival_dt)

    def __handle_event(self, event, arrival_dt):
        if isinstance(event, (stem.response.events.CircuitEvent, stem.response.events.CircMinorEvent)):
            if event.purpose is stem.CircPurpose.HS_CLIENT_GENERAL:
                self.__handle_circuit_general(event, arrival_dt)
            elif event.purpose in (stem.CircPurpose.HS_CLIENT_INTRO, stem.CircPurpose.HS_CLIENT_REND,
                                   stem.CircPurpose.HS_SERVICE_INTRO, stem.CircPurpose.HS_SERVICE_REND):
                self.__handle_circuit_hs(event, arrival_dt)
        elif isinstance(event, stem.response.events.StreamEvent):
            self.__handle_stream(event, arrival_dt)

    def __parse_line(self, line, do_simple):
        if not self.boot_succeeded:
            if re.search("Starting\storctl\sprogram\son\shost", line) is not None:
                parts = line.strip().split()
                if len(parts) < 11:
                    return True
                self.name = parts[10]
            if re.search("Bootstrapped\s100", line) is not None:
                self.boot_succeeded = True
            elif re.search("BOOTSTRAP", line) is not None and re.search("PROGRESS=100", line) is not None:
                self.boot_succeeded = True

        # parse with stem
        timestamps, sep, raw_event_str = line.partition(" 650 ")
        if sep == '':
            return True

        unix_ts = timestamps.strip().split()[2]
        arrival_dt = datetime.datetime.fromtimestamp(unix_ts)

        event = ControlMessage.from_str("{0} {1}".format(sep.strip(), raw_event_str.strip()))
        convert('EVENT', event)

        self.handle_torctl_event(event, arrival_dt)
        return True

    def parse(self, source, do_simple=True):
        source.open()
        for line in source:
            # ignore line parsing errors
            try:
                if self.__parse_line(line, do_simple):
                    continue
                else:
                    break
            except:
                continue
        source.close()

    def get_data(self):
        return {'streams':{}, 'circuits':{}}  # {'streams':self.streams, 'streams_summary': self.transfers_summary}

    def get_name(self):
        return self.name
