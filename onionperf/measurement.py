'''
Created on Oct 1, 2015

@author: rob
'''

import os, subprocess, threading, logging, time, socket, re
from lxml import etree

import monitor, model, util

def watchdog_task(self, subp, writable, done_ev):
    while not done_ev.wait(1):
        # timeout fired, done_ev is not yet set
        for line in iter(subp.stdout.readline(), ''):
            writable.write(line)

    # IF the process is still running, stop it
    if subp.poll is None:
        subp.stdout.close()  # avoid deadlocks from too much
        subp.terminate()
        subp.wait()

# class TorProcess(Process):
#
#     def __init__(self, bin_path, datadir_path, writable):
#         self.bin_path = bin_path
#         self.datadir_path = datadir_path
#         self.writable = writable
#         self.tor_subp = None
#         self.tor_monitor_proc = None
#         self.hs_service_id = None
#
#     def start(self, done_event, control_port=9050, socks_port=9000, hs_port_mapping=None):
#         if not os.path.exists(self.datadir_path):
#             os.makedirs(self.datadir_path)
#         os.chmod(self.datadir_path, 0700)
#
#         config = {
#             'ORPort': '0',
#             'DirPort': '0',
#             'ControlPort': str(control_port),
#             'SocksPort': str(socks_port),
#             'SocksListenAddress': '127.0.0.1',
#             'ClientOnly': '1',
#             # 'FascistFirewall': '1',
#             'WarnUnsafeSocks': '0',
#             'SafeLogging': '0',
#             'MaxCircuitDirtiness': '10 seconds',
#             'UseEntryGuards' : '0',
#             'DataDirectory': self.datadir_path,
#             'Log': [
#                 'NOTICE stdout',
#                 # 'INFO file .onionperf/client/tor/tor.log'.format(self.c_tor_datadir),
#             ],
#         }
#
#         self.tor_subp = stem.process.launch_tor_with_config(config, tor_cmd=self.bin_path, completion_percent=100, init_msg_handler=None, timeout=None, take_ownership=False)
#         self.control_port = control_port
#
#         # if self.writable is None:
#         #    self.tor_log_path = "{0}/onionperf.tor.log".format(self.datadir_path)
#         #    logging.info("logging Tor events from port {0} to {1}".format(control_port, self.tor_log_path))
#         #    self.writable = FileWritable(self.tor_log_path)
#
#         tor_monitor = monitor.TorMonitor(control_port, self.writable)
#         self.tor_monitor_proc = multiprocessing.Process(target=monitor.TorMonitor.run, args=(tor_monitor,))
#         self.tor_monitor_proc.start()
#
#         if hs_port_mapping is not None:
#             # TODO how do we check to make sure tor supports ephemeral HS (version >= 0.2.7.1-alpha)?
#             with stem.control.Controller.from_port(port=self.control_port) as torctl:
#                 torctl.authenticate()
#                 response = torctl.create_ephemeral_hidden_service(hs_port_mapping, detached=True, await_publication=True)
#                 self.hs_service_id = response.service_id
#
#     def stop(self):
#         if self.hs_service_id is not None:
#             with stem.control.Controller.from_port(port=self.control_port) as torctl:
#                 torctl.authenticate()
#                 torctl.remove_ephemeral_hidden_service(self.hs_service_id)
#         if self.tor_subp is not None and self.tor_subp.poll() is None:
#             self.tor_subp.terminate()
#             self.tor_subp.wait()
#             self.tor_subp = None
#         if self.tor_monitor_proc is not None:
#             self.tor_monitor_proc.terminate()
#             self.tor_monitor_proc.join()
#             self.tor_monitor_proc = None
#
#     def is_alive(self):
#         if self.tor_subp is not None and self.tor_subp.poll() is None and self.tor_monitor_proc is not None and self.tor_monitor_proc.is_alive():
#             return True
#         else:
#             return False

class Measurement(object):

    def __init__(self, tor_bin_path, tgen_bin_path, twistd_bin_path, datadir_path):
        self.tor_bin_path = tor_bin_path
        self.tgen_bin_path = tgen_bin_path
        self.twistd_bin_path = twistd_bin_path
        self.datadir_path = datadir_path
        self.threads = None
        self.done_event = None

    def run(self, do_onion=True, do_inet=False, do_local=False):
        self.threads = []
        self.done_event = threading.Event()

        # if ctrl-c is pressed, shutdown child processes properly
        try:
            logging.info("Bootstrapping started...")
            logging.info("Log files for the client and server processes will be placed in {0}".format(self.datadir_path))

            if do_local or do_onion or do_inet:
                self.__start_tgen_server()

            if do_onion:
                self.__start_tor_server()

            if do_onion or do_inet:
                self.__start_tor_client()

            server_urls = []
            if do_onion: server_urls.append("{0}.onion:58888".format(self.tor_server.hs_service_id))
            if do_inet: server_urls.append("{0}:58888".format(self.__get_ip_address()))
            if do_local: server_urls.append("127.0.0.1:58888")

            if len(server_urls) > 0:
                self.__start_tgen_client(server_urls)

            if do_local or do_onion or do_inet:
                self.__start_twisted()

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
            self.done_event.set()
            for t in self.threads: t.join()
            time.sleep(1)
            logging.disable(logging.NOTSET)

            logging.info("Child processes terminated")
            logging.info("Child process cleanup complete!")
            logging.info("Exiting")

    def __start_tgen_client(self, server_urls):
        logging.info("Starting tgen client process...")

        tgen_client_datadir = "{0}/tgen-client".format(self.datadir_path)
        if not os.path.exists(tgen_client_datadir): os.makedirs(tgen_client_datadir)

        tgen_client_confpath = "{0}/tgen.graphml.xml".format(tgen_client_datadir)
        if os.path.exists(tgen_client_confpath): os.remove(tgen_client_confpath)
        model.TorperfModel(tgen_port="58889", tgen_servers=server_urls, socksproxy="127.0.0.1:59001").dump_to_file(tgen_client_confpath)

        tgen_client_logpath = "{0}/onionperf.tgen.log".format(tgen_client_datadir)
        tgen_client_writable = util.FileWritable(tgen_client_logpath)
        logging.info("logging TGen client process output to {0}".format(tgen_client_logpath))

        tgen_client_subp = subprocess.Popen([self.tgen_bin_path, tgen_client_confpath], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        tgen_client_watchdog = threading.Thread(target=watchdog_task, args=(tgen_client_subp.stdout, tgen_client_writable, self.done_event))
        tgen_client_watchdog.start()
        self.threads.append(tgen_client_watchdog)

    def __start_tgen_server(self):
        logging.info("Starting tgen server process...")

        tgen_server_datadir = "{0}/tgen-server".format(self.datadir_path)
        if not os.path.exists(tgen_server_datadir): os.makedirs(tgen_server_datadir)

        tgen_server_confpath = "{0}/tgen.graphml.xml".format(tgen_server_datadir)
        if os.path.exists(tgen_server_confpath): os.remove(tgen_server_confpath)
        model.ListenModel(tgen_port="58888").dump_to_file(tgen_server_confpath)

        tgen_server_logpath = "{0}/onionperf.tgen.log".format(tgen_server_datadir)
        tgen_server_writable = util.FileWritable(tgen_server_logpath)
        logging.info("logging TGen server process output to {0}".format(tgen_server_logpath))

        tgen_server_subp = subprocess.Popen([self.tgen_bin_path, tgen_server_confpath], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        tgen_server_watchdog = threading.Thread(target=watchdog_task, args=(tgen_server_subp.stdout, tgen_server_writable, self.done_event))
        tgen_server_watchdog.start()
        self.threads.append(tgen_server_watchdog)

    def __start_twisted(self):
        logging.info("Starting Twisted server process...")

        twisted_datadir = "{0}/twisted-data".format(self.datadir_path)
        if not os.path.exists(twisted_datadir): os.makedirs(twisted_datadir)

        twisted_logpath = "{0}/onionperf.twisted.log".format(twisted_datadir)
        twisted_writable = util.FileWritable(twisted_logpath)
        logging.info("logging Twisted process output to {0}".format(twisted_logpath))

        twisted_docroot = "{0}/docroot".format(twisted_datadir)
        if not os.path.exists(twisted_docroot): os.makedirs(twisted_docroot)

        twisted_cmd = "{0} -n -l - web --path {1}".format(self.twistd_bin_path, twisted_docroot)
        twisted_subp = subprocess.Popen(twisted_cmd.split(), stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        twisted_watchdog = threading.Thread(target=watchdog_task, args=(twisted_subp.stdout, twisted_writable, self.done_event))
        twisted_watchdog.start()
        self.threads.append(twisted_watchdog)

    def __start_tor_client(self):
        pass
#                 logging.info("Starting tor client process...")
#
#                 tor_client_datadir = "{0}/tor-client".format(self.datadir_path)
#                 tor_client_logpath = "{0}/onionperf.tor.log".format(tor_client_datadir)
#                 logging.info("logging Tor events from port {0} to {1}".format(59051, tor_client_logpath))
#                 tor_client_writable = util.RotateFileWritable(tor_client_logpath)
#                 self.tor_client = TorProcess(self.tor_bin_path, tor_client_datadir, tor_client_writable)
#                 self.tor_client.start(self.done_event, control_port=59051, socks_port=59001, hs_port_mapping=None)


    def __start_tor_server(self):
        pass
#                 logging.info("Starting tor server process...")
#
#                 tor_server_datadir = "{0}/tor-server".format(self.datadir_path)
#                 tor_server_logpath = "{0}/onionperf.tor.log".format(tor_server_datadir)
#                 logging.info("logging Tor events from port {0} to {1}".format(59050, tor_server_logpath))
#                 tor_server_writable = util.FileWritable(tor_server_logpath)
#                 self.tor_server = TorProcess(self.tor_bin_path, tor_server_datadir, tor_server_writable)
#                 self.tor_server.start(self.done_event, control_port=59050, socks_port=0, hs_port_mapping={58888:58888})
#

    def __get_ip_address(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]

    def __generate_index(self):
        root = etree.Element("files")
        filepaths = [f for f in os.listdir(self.docroot_path) if os.path.isfile(os.path.abspath('/'.join([self.docroot_path, f])))]
        for filename in filepaths:
            e = etree.SubElement(root, "file")
            e.set("name", filename)
        with open("{0}/index.xml".format(self.docroot_path), 'wb') as f: print >> f, etree.tostring(root, pretty_print=True, xml_declaration=True)

    def __get_download_count(self, tgen_logpath):
        count = 0
        if tgen_logpath is not None and os.path.exists(tgen_logpath):
            with open(tgen_logpath, 'r') as fin:
                for line in fin:
                    if re.search("transfer-complete", line) is not None:
                        count += 1
        return count

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
