'''
Created on Oct 1, 2015

@author: rob
'''

import sys, os, shutil, subprocess, multiprocessing, argparse, logging, time
from signal import signal, SIGINT, SIG_IGN, SIGTERM
from itertools import cycle
from functools import partial

import stem
from stem import process, control
from stem.control import EventType, Controller
from stem.util import str_tools

logging.getLogger("stem").setLevel(logging.WARN)

class Measurement(object):
    '''
    classdocs
    '''
    torpath = None
    tgenpath = None
    burst_interval = None
    burst_num = None
    done_event = None
    s_tor_datadir = None
    s_tor_hsdir = None
    s_tor_onionurl = None
    s_tgen_process = None
    s_tor_p = None
    s_tor_logger_process = None
    c_tgen_process = None
    c_tor_p = None
    c_tor_logger_process = None

    def __init__(self, params):
        '''
        Constructor
        '''
        self.torpath = params.torpath
        self.tgenpath = params.tgenpath
        self.burst_interval = params.burst_interval
        self.burst_num = params.burst_num
        self.done_event = multiprocessing.Event()

    def run(self):
        # if ctrl-c is pressed, shutdown child processes properly
        try:
            logging.info("Starting tgen server process...")
            self.__start_tgen_server()
            logging.info("Starting tor server process...")
            self.__start_tor_server()
            logging.info("Starting tor client process...")
            self.__start_tor_client()
            logging.info("Starting tor logging processes...")
            self.__start_tor_loggers()
            logging.info("Pausing for 30 seconds to publish hidden service descriptor...")
            time.sleep(30)
            logging.info("Starting tgen client process using configured burst_num={0} and burst_interval={1}...".format(self.burst_num, self.burst_interval))
            self.__start_tgen_client()

            logging.info("Log files for the client and server porcesses are located in {0}".format(os.getcwd()))

            while True:
                logging.info("Heartbeat: {0} downloads have completed successfully".format(self.__get_download_count()))
                if self.__is_alive(): logging.info("All helper process seem to be alive :)")
                else: logging.warning("Some parallel components have died :(")
                logging.info("Main process will now sleep for 1 hour (helper processes run on their own schedule)")
                logging.info("press CTRL-C for graceful shutdown...")
                time.sleep(3600)

        except KeyboardInterrupt:
            logging.info("Interrupt received, please wait for graceful shutdown")

        finally:
            logging.info("Cleaning up child processes now...")

            logging.disable(logging.INFO)
            self.done_event.set()
            if self.c_tgen_process is not None: self.c_tgen_process.join()
            if self.s_tgen_process is not None: self.s_tgen_process.join()
            if self.c_tor_logger_process is not None: self.c_tor_logger_process.join()
            if self.s_tor_logger_process is not None: self.s_tor_logger_process.join()
            time.sleep(1)
            logging.disable(logging.NOTSET)

            logging.info("Child processes terminated")

            if self.s_tor_hsdir is not None:
                # self.server_tor_ctl.remove_hidden_service(self.server_hsdir)
                shutil.rmtree(self.s_tor_hsdir)

            logging.info("Child process cleanup complete!")
            logging.info("Exiting")

    def __get_download_count(self):
        count = 0
        tgen_log_path = ".onionperf/client/tgen/tgen.log"
        if os.path.exists(tgen_log_path):
            with open(tgen_log_path, 'r') as fin:
                for line in fin:
                    if line.find("transfer-complete") > -1: count += 1
        return count

    def __is_alive(self):
        alive = True
        if self.c_tgen_process is not None and not self.c_tgen_process.is_alive():
            logging.info("client tgen process is dead")
            alive = False
        if self.s_tgen_process is not None and not self.s_tgen_process.is_alive():
            logging.info("server tgen process is dead")
            alive = False
        if self.c_tor_p is not None and self.c_tor_p.poll() is not None:
            logging.info("client tor process is dead")
            alive = False
        if self.s_tor_p is not None and self.s_tor_p.poll() is not None:
            logging.info("server tor process is dead")
            alive = False
        if self.c_tor_logger_process is not None and not self.c_tor_logger_process.is_alive():
            logging.info("client tor logging process is dead")
            alive = False
        if self.s_tor_logger_process is not None and not self.s_tor_logger_process.is_alive():
            logging.info("server tor logging process is dead")
            alive = False
        return alive

    def __start_tgen_server(self):
        self.s_tgen_process = multiprocessing.Process(target=OnionPerf.__tgen_server_main, args=(self,))
        self.s_tgen_process.start()

    def __tgen_server_main(self):
        signal(SIGINT, SIG_IGN)  # ignore interrupts
        tgen_dir = ".onionperf/server/tgen"
        if not os.path.exists(tgen_dir): os.makedirs(tgen_dir)
        conffile = "{0}/tgen.graphml.xml".format(tgen_dir)
        if not os.path.exists(conffile):
            with open(conffile, 'wb') as f: print >> f, TGEN_SERVER_CONF,
        with open("{0}/tgen.log".format(tgen_dir), 'a') as logf:
            p = None
            while not self.done_event.is_set():
                p = subprocess.Popen([self.tgenpath, conffile], stdout=logf, stderr=logf)
                while not self.done_event.wait(5):  # while the timeout triggers
                    if p.poll() is not None:  # process has terminated
                        p.wait()  # collect child
                        p = None  # clear
                        break  # break out inner loop and restart process
            # if interupted and proc is still running, kill it
            if p is not None and p.poll() is None:
                p.terminate()
                p.wait()

    def __start_tgen_client(self):
        self.c_tgen_process = multiprocessing.Process(target=OnionPerf.__tgen_client_main, args=(self,))
        self.c_tgen_process.start()

    def __tgen_client_main(self):
        signal(SIGINT, SIG_IGN)  # ignore interrupts
        tgen_dir = ".onionperf/client/tgen"
        if not os.path.exists(tgen_dir): os.makedirs(tgen_dir)
        conffile = "{0}/tgen.graphml.xml".format(tgen_dir)
        with open("{0}/tgen.log".format(tgen_dir), 'a') as logf:
            sizes = cycle(DOWNLOAD_SIZES)
            p = None
            count = 0
            while not self.done_event.is_set():
                if os.path.exists(conffile): os.remove(conffile)
                with open(conffile, 'wb') as f: print >> f, TGEN_CLIENT_CONF_TEMPLATE.format(self.s_tor_onionurl, sizes.next()),
                p = subprocess.Popen([self.tgenpath, conffile], stdout=logf, stderr=logf)
                while not self.done_event.wait(5):  # while the timeout triggers
                    if p.poll() is not None:  # process has terminated
                        p.wait()  # collect child
                        p = None  # clear
                        break  # break out inner loop and restart process
                count += 1
                if count >= self.burst_num:
                    time.sleep(self.burst_interval)
                    count = 0
                else: time.sleep(10)  # give time for the circuit to expire
            # if interupted and proc is still running, kill it
            if p is not None and p.poll() is None:
                p.terminate()
                p.wait()

    def __start_tor_loggers(self):
        self.s_tor_logger_process = multiprocessing.Process(target=OnionPerf.__tor_logger_main, args=(self, 9050, ".onionperf/server/tor/tor.ctl.log"))
        self.s_tor_logger_process.start()
        self.c_tor_logger_process = multiprocessing.Process(target=OnionPerf.__tor_logger_main, args=(self, 9051, ".onionperf/client/tor/tor.ctl.log"))
        self.c_tor_logger_process.start()

    def __tor_logger_main(self, ctlport, logpath):
        signal(SIGINT, SIG_IGN)  # ignore interrupts
        with open(logpath, 'a') as logf:
            with stem.control.Controller.from_port(port=ctlport) as torctl:
                event_handler = partial(OnionPerf.__handle_tor_event, self, logf,)
                torctl.authenticate()
                torctl.add_event_listener(event_handler, stem.control.EventType.ORCONN, stem.control.EventType.CIRC, stem.control.EventType.STREAM, stem.control.EventType.BW, stem.control.EventType.GUARD, stem.control.EventType.INFO, stem.control.EventType.NOTICE, stem.control.EventType.WARN, stem.control.EventType.ERR, stem.control.EventType.HS_DESC, stem.control.EventType.BUILDTIMEOUT_SET, stem.control.EventType.DESCCHANGED, stem.control.EventType.NEWCONSENSUS, stem.control.EventType.NEWDESC, stem.control.EventType.STATUS_CLIENT, stem.control.EventType.STATUS_GENERAL, stem.control.EventType.STATUS_SERVER)
                # torctl.add_event_listener(event_handler, stem.control.EventType.CONN_BW, stem.control.EventType.CIRC_BW, stem.control.EventType.STREAM_BW, stem.control.EventType.TB_EMPTY, stem.control.EventType.HS_DESC_CONTENT)
                self.done_event.wait()
        time.sleep(1)

    def __handle_tor_event(self, logf, event):
        s = time.time()
        t = time.localtime(s)
        print >> logf, "{0} {1} {2}".format(time.strftime("%Y-%m-%d %H:%M:%S"), s, event.raw_content()),

    def __start_tor_client(self):
        self.c_tor_datadir = ".onionperf/client/tor/data"
        if not os.path.exists(self.c_tor_datadir): os.makedirs(self.c_tor_datadir)
        os.chmod(self.c_tor_datadir, 0700)

        config = {
            'ORPort': '0',
            'DirPort': '0',
            'ControlPort': '9051',
            'SocksPort': '9001',
            'SocksListenAddress': '127.0.0.1',
            'ClientOnly': '1',
            'FascistFirewall': '1',
            'WarnUnsafeSocks': '0',
            'SafeLogging': '0',
            'MaxCircuitDirtiness': '10 seconds',
            'UseEntryGuards' : '0',
            'DataDirectory': self.c_tor_datadir,
            'Log': [
                'NOTICE stdout',
                # 'INFO file .onionperf/client/tor/tor.log'.format(self.c_tor_datadir),
            ],
        }

        self.c_tor_p = stem.process.launch_tor_with_config(config, tor_cmd=self.torpath, completion_percent=100, init_msg_handler=None, timeout=None, take_ownership=True)

    def __start_tor_server(self):
        self.s_tor_datadir = ".onionperf/server/tor/data"
        if not os.path.exists(self.s_tor_datadir): os.makedirs(self.s_tor_datadir)
        os.chmod(self.s_tor_datadir, 0700)

        self.s_tor_hsdir = ".onionperf/server/tor/hs"
        if not os.path.exists(self.s_tor_hsdir): os.makedirs(self.s_tor_hsdir)
        os.chmod(self.s_tor_hsdir, 0700)

        config = {
            'ORPort': '0',
            'DirPort': '0',
            'ControlPort': '9050',
            'SocksPort': '9000',
            'SocksListenAddress': '127.0.0.1',
            'ClientOnly': '1',
            'FascistFirewall': '1',
            'WarnUnsafeSocks': '0',
            'SafeLogging': '0',
            'MaxCircuitDirtiness': '10 seconds',
            'UseEntryGuards' : '0',
            'DataDirectory': self.s_tor_datadir,
            'HiddenServiceDir': self.s_tor_hsdir,
            'HiddenServicePort': '80 127.0.0.1:8888',
            'Log': [
                'NOTICE stdout',
                # 'INFO file .onionperf/server/tor/tor.log',
            ],
        }

        self.s_tor_p = stem.process.launch_tor_with_config(config, tor_cmd=self.torpath, completion_percent=100, init_msg_handler=None, timeout=None, take_ownership=True)

        with open("{0}/hostname".format(self.s_tor_hsdir), 'r') as f:
            self.s_tor_onionurl = f.readline().strip()
