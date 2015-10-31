'''
Created on Oct 10, 2015

@author: rob
'''

import time, stem
from functools import partial
from stem.control import EventType, Controller

def get_supported_torctl_events():
    return list(EventType)

class TorMonitor(object):

    def __init__(self, tor_ctl_port, writable, events=get_supported_torctl_events()):
        self.tor_ctl_port = tor_ctl_port
        self.writable = writable
        self.events = events

    def run(self, done_ev=None):
        with stem.control.Controller.from_port(port=self.tor_ctl_port) as torctl:
            torctl.authenticate()

            # register for async events!
            # some events are only supported in newer versions of tor, so ignore errors from older tors
            event_handler = partial(TorMonitor.__handle_tor_event, self, self.writable,)
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
                while done_ev is None or not done_ev.is_set():
                    # if self.filepath != '-' and os.path.exists(self.filepath):
                    #    with open(self.filepath, 'rb') as sizef:
                    #        msg = "tor-ctl-logger[port={0}] logged {1} bytes to {2}, press CTRL-C to quit".format(self.tor_ctl_port, os.fstat(sizef.fileno()).st_size, self.filepath)
                    #        logging.info(msg)
                    time.sleep(1)
            except KeyboardInterrupt:
                pass  # the user hit ctrl+c

        self.writable.close()

    def __handle_tor_event(self, writable, event):
        self.__log(writable, event.raw_content())

    def __log(self, writable, msg):
        s = time.time()
        # t = time.localtime(s)
        writable.write("{0} {1} {2}".format(time.strftime("%Y-%m-%d %H:%M:%S"), s, msg))

def tor_monitor_run(tor_ctl_port, writable, events, done_ev):
    torctl_monitor = TorMonitor(tor_ctl_port, writable, events)
    torctl_monitor.run(done_ev=done_ev)