'''
Created on Oct 1, 2015

@author: rob
'''

import os, subprocess, multiprocessing, logging, time, socket
from signal import signal, SIGINT, SIG_IGN

from flask import Flask
from lxml import etree

import stem.process
from abc import abstractmethod, ABCMeta

import monitor, model
import re

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
        self.tgen_subp = None
        self.tgen_log_path = None

    def start(self, done_event):
        self.tgen_proc = multiprocessing.Process(target=TGenProcess.run, args=(self, done_event,))
        self.tgen_proc.start()

    def run(self, done_event):
        signal(SIGINT, SIG_IGN)  # ignore interrupts

        conffile = "{0}/tgen.graphml.xml".format(self.datadir_path)
        if not os.path.exists(self.datadir_path):
            os.makedirs(self.datadir_path)
        if os.path.exists(conffile):
            os.remove(conffile)
        self.tgen_model.dump_to_file(conffile)

        self.tgen_log_path = "{0}/onionperf.tgen.log".format(self.datadir_path)
        logging.info("logging TGen process output to {0}".format(self.tgen_log_path))
        with open(self.tgen_log_path, 'a') as logf:
            self.tgen_subp = None
            while not done_event.is_set():
                self.tgen_subp = subprocess.Popen([self.bin_path, conffile], stdout=logf, stderr=logf)
                while not done_event.wait(5):  # while the timeout triggers
                    if self.tgen_subp.poll() is not None:  # process has terminated
                        self.tgen_subp.wait()  # collect child
                        self.tgen_subp = None  # clear
                        break  # break out inner loop and restart process

    def is_alive(self):
        if self.tgen_subp is not None and self.tgen_subp.poll() is None and self.tgen_proc is not None and self.tgen_proc.is_alive():
            return True
        else:
            return False

    def stop(self):
        if self.tgen_subp is not None and self.tgen_subp.poll() is None:
            self.tgen_subp.terminate()
            self.tgen_subp.wait()
            self.tgen_subp = None
        if self.tgen_proc is not None:
            self.tgen_proc.terminate()
            self.tgen_proc.join()
            self.tgen_proc = None

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
        self.tor_subp = None
        self.tor_monitor_proc = None
        self.hs_service_id = None

    def start(self, done_event, control_port=9050, socks_port=9000, hs_port_mapping=None):
        if not os.path.exists(self.datadir_path):
            os.makedirs(self.datadir_path)
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

        self.tor_subp = stem.process.launch_tor_with_config(config, tor_cmd=self.bin_path, completion_percent=100, init_msg_handler=None, timeout=None, take_ownership=False)
        self.control_port = control_port

        self.tor_log_path = "{0}/onionperf.tor.log".format(self.datadir_path)
        logging.info("logging Tor events from port {0} to {1}".format(control_port, self.tor_log_path))
        tor_monitor = monitor.TorMonitor(control_port, self.tor_log_path)
        self.tor_monitor_proc = multiprocessing.Process(target=monitor.TorMonitor.run, args=(tor_monitor,))
        self.tor_monitor_proc.start()

        if hs_port_mapping is not None:
            # TODO how do we check to make sure tor supports ephemeral HS (version >= 0.2.7.1-alpha)?
            with stem.control.Controller.from_port(port=self.control_port) as torctl:
                torctl.authenticate()
                response = torctl.create_ephemeral_hidden_service(hs_port_mapping, detached=True, await_publication=True)
                self.hs_service_id = response.service_id

    def stop(self):
        if self.hs_service_id is not None:
            with stem.control.Controller.from_port(port=self.control_port) as torctl:
                torctl.authenticate()
                torctl.remove_ephemeral_hidden_service(self.hs_service_id)
        if self.tor_subp is not None and self.tor_subp.poll() is None:
            self.tor_subp.terminate()
            self.tor_subp.wait()
            self.tor_subp = None
        if self.tor_monitor_proc is not None:
            self.tor_monitor_proc.terminate()
            self.tor_monitor_proc.join()
            self.tor_monitor_proc = None

    def is_alive(self):
        if self.tor_subp is not None and self.tor_subp.poll() is None and self.tor_monitor_proc is not None and self.tor_monitor_proc.is_alive():
            return True
        else:
            return False

class FlaskServerProcess(Process):

    def __init__(self, docroot_path, url_path="/onionperf"):
        self.docroot_path = docroot_path
        self.url_path = url_path
        self.flask_proc = None
        self.watchdog_proc = None

        self.app = Flask(__name__, static_folder=self.docroot_path, static_url_path=self.url_path)
        @self.app.route('{0}/<path:path>'.format(self.url_path))
        def static_proxy(path):
            return self.app.send_static_file(path)

    def start(self, done_event):
        if not os.path.exists(self.docroot_path):
            os.makedirs(self.datadir_path)
        self.watchdog_proc = multiprocessing.Process(target=FlaskServerProcess.run, args=(self, done_event,))
        self.watchdog_proc.start()

    def run(self, done_event):
        signal(SIGINT, SIG_IGN)  # ignore interrupts

        self.flask_proc = None
        while not done_event.is_set():
            self.flask_proc = multiprocessing.Process(target=FlaskServerProcess.__run_flask, args=(self,))
            self.flask_proc.start()
            while not done_event.wait(5):  # while the timeout triggers
                if self.flask_proc is None or not self.flask_proc.is_alive():  # process has terminated
                    self.flask_proc.join()  # collect child
                    self.flask_proc = None  # clear
                    break  # break out inner loop and restart process, or stop watchdog
        # if we got here because done_event was set, make sure to stop the flask server
        if self.flask_proc is not None:
            self.flask_proc.terminate()
            self.flask_proc.join()
            self.flask_proc = None

    def __run_flask(self):
        self.app.run(debug=False, host='0.0.0.0')

    def stop(self):
        # the flask_proc was created inside the watchdog proc, so i dont know if we ever have access to that here
        if self.flask_proc is not None:
            self.flask_proc.terminate()
            self.flask_proc.join()
            self.flask_proc = None
        if self.watchdog_proc is not None:
            self.watchdog_proc.terminate()
            self.watchdog_proc.join()
            self.watchdog_proc = None

    def is_alive(self):
        if self.watchdog_proc is not None and self.watchdog_proc.is_alive() and self.flask_proc is not None and self.flask_proc.is_alive():
            return True
        else:
            return False

    def generate_index(self):
        root = etree.Element("files")
        filepaths = [f for f in os.listdir(self.docroot_path) if os.path.isfile(os.path.abspath('/'.join([self.docroot_path, f])))]
        for filename in filepaths:
            e = etree.SubElement(root, "file")
            e.set("name", filename)
        with open("{0}/index.xml".format(self.docroot_path), 'wb') as f: print >> f, etree.tostring(root, pretty_print=True, xml_declaration=True)

class Measurement(object):

    def __init__(self, tor_bin_path, tgen_bin_path, datadir_path):
        self.tor_bin_path = tor_bin_path
        self.tgen_bin_path = tgen_bin_path
        self.datadir_path = datadir_path
        self.done_event = None
        self.tgen_server = None
        self.tor_server = None
        self.tor_client = None
        self.tgen_client = None
        self.flask_server = None

    def run(self, do_onion=True, do_inet=False, do_local=False):
        # if ctrl-c is pressed, shutdown child processes properly
        try:
            logging.info("Bootstrapping started...")
            logging.info("Log files for the client and server processes will be placed in {0}".format(self.datadir_path))
            self.done_event = multiprocessing.Event()

            logging.info("Starting tgen server process...")
            tgen_server_model = model.ListenModel(tgen_port="58888")
            self.tgen_server = TGenProcess(self.tgen_bin_path, "{0}/tgen-server".format(self.datadir_path), tgen_server_model)
            self.tgen_server.start(self.done_event)

            logging.info("Starting tor server process...")
            self.tor_server = TorProcess(self.tor_bin_path, "{0}/tor-server".format(self.datadir_path))
            self.tor_server.start(self.done_event, control_port=9050, socks_port=0, hs_port_mapping={58888:58888})

            logging.info("Starting tor client process...")
            self.tor_client = TorProcess(self.tor_bin_path, "{0}/tor-client".format(self.datadir_path))
            self.tor_client.start(self.done_event, control_port=9051, socks_port=9001, hs_port_mapping=None)

            server_urls = []
            if do_onion:
                server_urls.append("{0}.onion:58888".format(self.tor_server.hs_service_id))
            if do_inet:
                server_urls.append("{0}:58888".format(self.__get_ip_address()))
            if do_local:
                server_urls.append("127.0.0.1:58888")

            if len(server_urls) > 0:
                logging.info("Starting tgen client process...")
                tgen_client_model = model.TorperfModel(tgen_port="58889", tgen_servers=server_urls, socksproxy="127.0.0.1:9001")
                self.tgen_client = TGenProcess(self.tgen_bin_path, "{0}/tgen-client".format(self.datadir_path), tgen_client_model)
                self.tgen_client.start(self.done_event)

            logging.info("Starting Flask server process...")
            self.flask_server = FlaskServerProcess("{0}/flask-docroot".format(self.datadir_path))
            self.flask_server.start()

            logging.info("Bootstrapping finished, entering heartbeat loop")
            while True:
                logging.info("Heartbeat: {0} downloads have completed successfully".format(self.tgen_client.get_download_count()))
                if self.__is_alive():
                    logging.info("All helper process seem to be alive :)")
                else:
                    logging.warning("Some parallel components have died :(")
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

            if self.tgen_client is not None:
                self.tgen_client.stop()
            if self.tor_client is not None:
                self.tor_client.stop()
            if self.tor_server is not None:
                self.tor_server.stop()
            if self.tgen_server is not None:
                self.tgen_server.stop()
            if self.flask_server is not None:
                self.flask_server.stop()

            time.sleep(1)
            logging.disable(logging.NOTSET)

            logging.info("Child processes terminated")
            logging.info("Child process cleanup complete!")
            logging.info("Exiting")

    def __get_ip_address(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]

    def __is_alive(self):
        alive = True
        if self.tgen_server is not None and not self.tgen_server.is_alive():
            logging.warning("server tgen process is dead")
            alive = False
        if self.tor_server is not None and not self.tor_server.is_alive():
            logging.warning("server tor process is dead")
            alive = False
        if self.tor_client is not None and not self.tor_client.is_alive():
            logging.warning("client tor process is dead")
            alive = False
        if self.tgen_client is not None and not self.tgen_client.is_alive():
            logging.warning("client tgen process is dead")
            alive = False
        if self.flask_server is not None and not self.flask_server.is_alive():
            logging.warning("flask server process is dead")
            alive = False
        return alive
