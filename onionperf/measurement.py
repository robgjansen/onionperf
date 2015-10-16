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
from abc import abstractmethod, ABCMeta

import monitor, model
import re

logging.getLogger("stem").setLevel(logging.WARN)

class Process(object):

    __metaclass__ = ABCMeta

    @abstractmethod
    def start(self, done_event):
        pass

    @abstractmethod
    def is_alive(self):
        pass

    @abstractmethod
    def stop(self):
        pass

class TGenProcess(Process):

    def __init__(self, bin_path, datadir_path, tgen_model):
        self.bin_path = bin_path
        self.datadir_path = datadir_path
        self.tgen_model = tgen_model
        self.tgen_proc = None
        self.tgen_p = None
        self.tgen_log_path = None

    def start(self, done_event):
        self.tgen_proc = multiprocessing.Process(target=TGenProcess.run, args=(self, done_event,))
        self.tgen_proc.start()

    def run(self, done_event):
        signal(SIGINT, SIG_IGN)  # ignore interrupts

        conffile = "{0}/tgen.graphml.xml".format(self.datadir_path)
        if not os.path.exists(self.datadir_path): os.makedirs(self.datadir_path)
        if os.path.exists(conffile):
            os.remove(conffile)
        self.tgen_model.dump_to_file(conffile)

        self.tgen_log_path = "{0}/onionperf.tgen.log".format(self.datadir_path)
        with open(self.tgen_log_path, 'a') as logf:
            self.tgen_p = None
            while not done_event.is_set():
                self.tgen_p = subprocess.Popen([self.bin_path, conffile], stdout=logf, stderr=logf)
                while not done_event.wait(5):  # while the timeout triggers
                    if self.tgen_p.poll() is not None:  # process has terminated
                        self.tgen_p.wait()  # collect child
                        self.tgen_p = None  # clear
                        break  # break out inner loop and restart process
            # if interupted and proc is still running, kill it
            if self.tgen_p is not None and self.tgen_p.poll() is None:
                self.tgen_p.terminate()
                self.tgen_p.wait()

    def is_alive(self):
        if self.tgen_proc is not None and self.tgen_proc.is_alive():
            return True
        else:
            return False

    def stop(self):
        if self.tgen_p is not None and self.tgen_proc is not None:
            self.tgen_p.terminate()
            self.tgen_proc.join()
            self.tgen_proc = None
            self.tgen_p = None

    def get_download_count(self):
        count = 0
        if self.tgen_log_path is not None and os.path.exists(self.tgen_log_path):
            with open(self.tgen_log_path, 'r') as fin:
                for line in fin:
                    if re.search("transfer-complete", line) is not None:
                        count += 1
        return count

class TorProcess(Process):

    def __init__(self, bin_path, datadir_path):
        self.bin_path = bin_path
        self.datadir_path = datadir_path
        self.tor_stem_p = None
        self.tor_monitor_proc = None
        self.self.hs_service_id = None

    def start(self, done_event, control_port=9050, socks_port=9000, hs_port_mapping=None):
        if not os.path.exists(self.datadir_path): os.makedirs(self.datadir_path)
        os.chmod(self.datadir_path, 0700)

        config = {
            'ORPort': '0',
            'DirPort': '0',
            'ControlPort': str(control_port),
            'SocksPort': str(socks_port),
            'SocksListenAddress': '127.0.0.1',
            'ClientOnly': '1',
            # 'FascistFirewall': '1',
            'WarnUnsafeSocks': '0',
            'SafeLogging': '0',
            'MaxCircuitDirtiness': '10 seconds',
            'UseEntryGuards' : '0',
            'DataDirectory': self.datadir_path,
            'Log': [
                'NOTICE stdout',
                # 'INFO file .onionperf/client/tor/tor.log'.format(self.c_tor_datadir),
            ],
        }

        self.tor_stem_p = stem.process.launch_tor_with_config(config, tor_cmd=self.bin_path, completion_percent=100, init_msg_handler=None, timeout=None, take_ownership=True)

        tor_monitor = monitor.TorMonitor(control_port, "{0}/onionperf.tor.log".format(self.datadir_path))
        self.tor_monitor_proc = multiprocessing.Process(target=monitor.TorMonitor.run, args=(tor_monitor,))
        self.tor_monitor_proc.start()

        if hs_port_mapping is not None:
            # TODO how do we check to make sure tor supports ephemeral HS (version >= 0.2.7.1-alpha)?
            with stem.control.Controller.from_port(port=self.tor_ctl_port) as torctl:
                torctl.authenticate()
                response = torctl.create_ephemeral_hidden_service(hs_port_mapping, detached=True, await_publication=True)
                self.hs_service_id = response.service_id

    def stop(self):
        if self.hs_service_id is not None:
            with stem.control.Controller.from_port(port=self.tor_ctl_port) as torctl:
                torctl.authenticate()
                torctl.remove_ephemeral_hidden_service(self.hs_service_id)
        if self.tor_monitor_proc is not None:
            self.tor_monitor_proc.terminate()
            self.tor_monitor_proc.join()
            self.tor_monitor_proc = None

    def is_alive(self):
        alive = False
        if (self.tor_stem_p is not None and self.tor_stem_p.poll() is not None) and (self.tor_monitor_proc is not None and self.tor_monitor_proc.is_alive()):
            alive = True
        return alive

class Measurement(object):

    def __init__(self, tor_bin_path, tgen_bin_path, datadir_path):
        self.tor_bin_path = tor_bin_path
        self.tgen_bin_path = tgen_bin_path
        self.datadir_path = datadir_path
        self.tgen_client = None
        self.tgen_server = None
        self.done_event = None

    def run(self):
        # if ctrl-c is pressed, shutdown child processes properly
        try:
            self.done_event = multiprocessing.Event()

            logging.info("Starting tgen server process...")
            tgen_server_model = model.ListenModel(tgen_port="58888")
            self.tgen_server = TGenProcess(self.tgen_bin_path, "{0}/tgen-server".format(self.datadir_path), tgen_server_model)
            self.tgen_server.start(self.done_event)

            # logging.info("Starting tor server process...")


            # logging.info("Starting tor client process...")


            logging.info("Starting tgen client process...")
            tgen_client_model = model.TorperfModel(tgen_port="58889", tgen_servers=["127.0.0.1:58888"])
            self.tgen_client = TGenProcess(self.tgen_bin_path, "{0}/tgen-client".format(self.datadir_path), tgen_client_model)
            self.tgen_client.start(self.done_event)

            logging.info("Log files for the client and server processes are located in {0}".format(self.datadir_path))

            while True:
                logging.info("Heartbeat: {0} downloads have completed successfully".format(self.tgen_client.get_download_count()))
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
            if self.done_event is not None:
                self.done_event.set()

            if self.tgen_server is not None: self.tgen_server.stop()
            if self.tgen_client is not None: self.tgen_client.stop()

            time.sleep(1)
            logging.disable(logging.NOTSET)

            logging.info("Child processes terminated")
            logging.info("Child process cleanup complete!")
            logging.info("Exiting")

    def __is_alive(self):
        alive = True
        if self.tgen_server is not None and not self.tgen_server.is_alive():
            logging.info("server tgen process is dead")
            alive = False
        if self.tgen_client is not None and not self.tgen_client.is_alive():
            logging.info("client tgen process is dead")
            alive = False
        return alive
