'''
Created on Oct 10, 2015

@author: rob
'''

import time, stem
from functools import partial
from stem.control import EventType, Controller

import util

class TorMonitor(object):

    def __init__(self, tor_ctl_port, filepath, events=['ORCONN', 'CIRC', 'STREAM', 'BW', 'GUARD', 'INFO', 'NOTICE', 'WARN', 'ERR', 'HS_DESC', 'BUILDTIMEOUT_SET', 'DESCCHANGED', 'NEWCONSENSUS', 'NEWDESC', 'STATUS_CLIENT', 'STATUS_GENERAL', 'STATUS_SERVER', 'CONN_BW', 'CIRC_BW', 'STREAM_BW', 'TB_EMPTY', 'HS_DESC_CONTENT']):
        self.tor_ctl_port = tor_ctl_port
        self.filepath = filepath
        self.events = events

    def run(self):
        sink = util.DataSink(self.filepath)
        sink.open()
        logfile = sink.get()

        with stem.control.Controller.from_port(port=self.tor_ctl_port) as torctl:
            torctl.authenticate()

            # register for async events!
            # some events are only supported in newer versions of tor, so ignore errors from older tors
            event_handler = partial(TorMonitor.__handle_tor_event, self, logfile,)
            for e in self.events:
                if e in EventType:
                    # try to add all events that this stem supports
                    # silently ignore those that our Tor does not support
                    try:
                        torctl.add_event_listener(event_handler, EventType[e])
                    except:
                        pass

            # let stem run its threads and log all of the events, until user interrupts
            try:
                while True:
                    # if self.filepath != '-' and os.path.exists(self.filepath):
                    #    with open(self.filepath, 'rb') as sizef:
                    #        msg = "tor-ctl-logger[port={0}] logged {1} bytes to {2}, press CTRL-C to quit".format(self.tor_ctl_port, os.fstat(sizef.fileno()).st_size, self.filepath)
                    #        logging.info(msg)
                    time.sleep(60)
            except KeyboardInterrupt:
                pass  # the user hit ctrl+c

        sink.close()

    def __handle_tor_event(self, logfile, event):
        self.__log(logfile, event.raw_content())

    def __log(self, logfile, msg):
        s = time.time()
        # t = time.localtime(s)
        print >> logfile, "{0} {1} {2}".format(time.strftime("%Y-%m-%d %H:%M:%S"), s, msg),
