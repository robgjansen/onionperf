'''
  OnionPerf
  Authored by Rob Jansen, 2015
  See LICENSE for licensing information
'''

import datetime
from time import sleep
from socket import gethostname
from functools import partial

# stem imports
from stem.control import EventType, Controller, Signal

def get_supported_torctl_events():
    return list(EventType)

class TorMonitor(object):

    def __init__(self, tor_ctl_port, writable, events=get_supported_torctl_events()):
        self.tor_ctl_port = tor_ctl_port
        self.writable = writable
        self.events = events

    def run(self, newnym_interval_seconds=None, done_ev=None):
        with Controller.from_port(port=self.tor_ctl_port) as torctl:
            torctl.authenticate()

            vers_str = "Starting torctl program on host {2} using Tor version {0} status={1}\n".format(torctl.get_info('version'), torctl.get_info('status/version/current'), gethostname())
            self.__log(self.writable, vers_str)

            boot_str = "{0}\n".format(torctl.get_info('status/bootstrap-phase'))
            self.__log(self.writable, boot_str)

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
                interval_count = 0
                while done_ev is None or not done_ev.is_set():
                    # if self.filepath != '-' and os.path.exists(self.filepath):
                    #    with open(self.filepath, 'rb') as sizef:
                    #        msg = "tor-ctl-logger[port={0}] logged {1} bytes to {2}, press CTRL-C to quit".format(self.tor_ctl_port, os.fstat(sizef.fileno()).st_size, self.filepath)
                    #        logging.info(msg)
                    sleep(1)
                    interval_count += 1
                    if newnym_interval_seconds is not None and interval_count >= newnym_interval_seconds:
                        interval_count = 0
                        torctl.signal(Signal.NEWNYM)
            except KeyboardInterrupt:
                pass  # the user hit ctrl+c

        self.writable.close()

    def __handle_tor_event(self, writable, event):
        self.__log(writable, event.raw_content())

    def __log(self, writable, msg):
        now = datetime.datetime.now()
        utcnow = datetime.datetime.utcnow()
        epoch = datetime.datetime(1970, 1, 1)
        unix_ts = (utcnow - epoch).total_seconds()
        writable.write("{0} {1:.02f} {2}".format(now.strftime("%Y-%m-%d %H:%M:%S"), unix_ts, msg))

def tor_monitor_run(tor_ctl_port, writable, events, newnym_interval_seconds, done_ev):
    torctl_monitor = TorMonitor(tor_ctl_port, writable, events)
    torctl_monitor.run(newnym_interval_seconds=newnym_interval_seconds, done_ev=done_ev)