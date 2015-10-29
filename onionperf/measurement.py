'''
Created on Oct 1, 2015

@author: rob
'''

import os, subprocess, threading, Queue, logging, time, socket, re
import stem, stem.process, stem.version, stem.util.str_tools
from lxml import etree

import monitor, model, util

def getlines_task(instream, q):
    for line in iter(instream.readline, b''): q.put(line)

def watchdog_task(subp, writable, done_ev):
    # get another helper to block on the subprocess stdout
    q = Queue.Queue()
    t = threading.Thread(target=getlines_task, args=(subp.stdout, q))
    # t.setDaemon(True)
    t.start()

    while subp.poll() is None and done_ev.is_set() is False:
        # we should still be collecting output
        try:
            while True:
                line = q.get(True, 1)
                writable.write(line)
        except Queue.Empty:
            continue

    # if the process is still running, stop it
    if subp.poll() is None:  # no exit code to collect
        subp.terminate()
        subp.wait()

    # flush any remaining lines
    subp.stdout.close()
    # t.join()
    while not q.empty(): writable.write(q.get_nowait())
    writable.close()

class Measurement(object):

    def __init__(self, tor_bin_path, tgen_bin_path, twistd_bin_path, datadir_path):
        self.tor_bin_path = tor_bin_path
        self.tgen_bin_path = tgen_bin_path
        self.twistd_bin_path = twistd_bin_path
        self.datadir_path = datadir_path
        self.threads = None
        self.done_event = None
        self.hs_service_id = None

    def run(self, do_onion=True, do_inet=True):
        self.threads = []
        self.done_event = threading.Event()

        # if ctrl-c is pressed, shutdown child processes properly
        try:
            # make sure tor supports ephemeral HS (version >= 0.2.7.1-alpha)?
            if do_onion and stem.version.get_system_tor_version(self.tor_bin_path) < stem.version.Requirement.ADD_ONION:
                logging.warning("OnionPerf in onion mode requires Tor version >= 0.2.7.1-alpha, aborting")
                return

            logging.info("Bootstrapping started...")
            logging.info("Log files for the client and server processes will be placed in {0}".format(self.datadir_path))

            if do_onion or do_inet:
                self.__start_tgen_server()

            if do_onion:
                self.__start_tor_server()

            if do_onion or do_inet:
                self.__start_tor_client()

            server_urls = []
            if do_onion and self.hs_service_id is not None: server_urls.append("{0}.onion:58888".format(self.hs_service_id))
            if do_inet: server_urls.append("{0}:58888".format(self.__get_ip_address()))

            if do_onion or do_inet:
                assert len(server_urls) > 0
                tgen_client_logpath = self.__start_tgen_client(server_urls)
                self.__start_twistd()

                logging.info("Bootstrapping finished, entering heartbeat loop")
                time.sleep(1)
                while True:
                    logging.info("Heartbeat: {0} downloads have completed successfully".format(self.__get_download_count(tgen_client_logpath)))
                    if self.__is_alive():
                        logging.info("All helper processes seem to be alive :)")
                    else:
                        logging.warning("Some parallel components have died :(")
                        logging.info("Exiting now, call run() again to attempt a restart")
                        break
                    logging.info("Main process will now sleep for 1 hour (helper processes run on their own schedule)")
                    logging.info("press CTRL-C for graceful shutdown...")
                    time.sleep(3600)
            else:
                logging.info("No measurement mode set, nothing to do")

        except KeyboardInterrupt:
            logging.info("Interrupt received, please wait for graceful shutdown")
            self.__is_alive()
        finally:
            logging.info("Cleaning up child processes now...")

            if self.hs_service_id is not None:
                with stem.control.Controller.from_port(port=self.hs_control_port) as torctl:
                    torctl.authenticate()
                    torctl.remove_ephemeral_hidden_service(self.hs_service_id)

            logging.disable(logging.INFO)
            self.done_event.set()
            for t in self.threads: t.join()
            time.sleep(1)
            logging.disable(logging.NOTSET)

            logging.info("Child processes terminated")
            logging.info("Child process cleanup complete!")
            logging.info("Exiting")

    def __start_tgen_client(self, server_urls):
        return self.__start_tgen("client", 58889, 59001, server_urls)

    def __start_tgen_server(self):
        return self.__start_tgen("server", 58888)

    def __start_tgen(self, name, tgen_port, socks_port=None, server_urls=None):
        logging.info("Starting TGen {0} process...".format(name))

        tgen_datadir = "{0}/tgen-{1}".format(self.datadir_path, name)
        if not os.path.exists(tgen_datadir): os.makedirs(tgen_datadir)

        tgen_confpath = "{0}/tgen.graphml.xml".format(tgen_datadir)
        if os.path.exists(tgen_confpath): os.remove(tgen_confpath)
        if socks_port is None:
            model.ListenModel(tgen_port="{0}".format(tgen_port)).dump_to_file(tgen_confpath)
            logging.info("tgen server running at 0.0.0.0:{0}".format(tgen_port))
        else:
            model.TorperfModel(tgen_port="{0}".format(tgen_port), tgen_servers=server_urls, socksproxy="127.0.0.1:{0}".format(socks_port)).dump_to_file(tgen_confpath)

        tgen_logpath = "{0}/onionperf.tgen.log".format(tgen_datadir)
        tgen_writable = util.FileWritable(tgen_logpath)
        logging.info("logging TGen client process output to {0}".format(tgen_logpath))

        tgen_subp = subprocess.Popen([self.tgen_bin_path, tgen_confpath], cwd=tgen_datadir, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        tgen_watchdog = threading.Thread(target=watchdog_task, name="tgen_{0}_watchdog".format(name), args=(tgen_subp, tgen_writable, self.done_event))
        tgen_watchdog.start()
        self.threads.append(tgen_watchdog)

        return tgen_logpath

    def __start_twistd(self):
        logging.info("Starting Twistd server process...")

        twisted_datadir = "{0}/twisted-data".format(self.datadir_path)
        if not os.path.exists(twisted_datadir): os.makedirs(twisted_datadir)

        twisted_logpath = "{0}/onionperf.twisted.log".format(twisted_datadir)
        twisted_writable = util.FileWritable(twisted_logpath)
        logging.info("logging Twisted process output to {0}".format(twisted_logpath))

        twisted_docroot = "{0}/docroot".format(twisted_datadir)
        if not os.path.exists(twisted_docroot): os.makedirs(twisted_docroot)
        self.__generate_index(twisted_docroot)

        twisted_cmd = "{0} -n -l - web --port 50080 --path {1}".format(self.twistd_bin_path, twisted_docroot)
        twisted_subp = subprocess.Popen(twisted_cmd.split(), cwd=twisted_datadir, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        twisted_watchdog = threading.Thread(target=watchdog_task, name="twistd_watchdog", args=(twisted_subp, twisted_writable, self.done_event))
        twisted_watchdog.start()
        self.threads.append(twisted_watchdog)
        logging.info("twistd web server running at 0.0.0.0:{0}".format(50080))

        return twisted_logpath

    def __start_tor_client(self):
        return self.__start_tor("client", 59051, 59001)

    def __start_tor_server(self):
        return self.__start_tor("server", 59050, 59000, {58888: 58888})

    def __start_tor(self, name, control_port, socks_port, hs_port_mapping=None):
        logging.info("Starting Tor {0} process...".format(name))

        tor_datadir = "{0}/tor-{1}".format(self.datadir_path, name)
        if not os.path.exists(tor_datadir): os.makedirs(tor_datadir)

        tor_config_template = "ORPort 0\nDirPort 0\nControlPort {0}\nSocksPort {1}\nSocksListenAddress 127.0.0.1\nClientOnly 1\n\
WarnUnsafeSocks 0\nSafeLogging 0\nMaxCircuitDirtiness 10 seconds\nUseEntryGuards 0\nDataDirectory {2}\nLog INFO stdout\n"
        tor_config = tor_config_template.format(control_port, socks_port, tor_datadir)

        tor_logpath = "{0}/onionperf.tor.log".format(tor_datadir)
        tor_writable = util.FileWritable(tor_logpath)
        logging.info("Logging Tor {0} process output to {1}".format(name, tor_logpath))

        # tor_subp = stem.process.launch_tor_with_config(tor_config, tor_cmd=self.tor_bin_path, completion_percent=100, init_msg_handler=None, timeout=None, take_ownership=False)
        tor_cmd = "{0} -f -".format(self.tor_bin_path)
        tor_subp = subprocess.Popen(tor_cmd.split(), cwd=tor_datadir, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE)
        tor_subp.stdin.write(stem.util.str_tools._to_bytes(tor_config))
        tor_subp.stdin.close()

        # wait for Tor to bootstrap
        boot_re = re.compile('Bootstrapped 100')
        for line in iter(tor_subp.stdout.readline, b''):
            tor_writable.write(line)
            if boot_re.search(line): break

        tor_watchdog = threading.Thread(target=watchdog_task, name="tor_{0}_watchdog".format(name), args=(tor_subp, tor_writable, self.done_event))
        tor_watchdog.start()
        self.threads.append(tor_watchdog)

        torctl_logpath = "{0}/onionperf.torctl.log".format(tor_datadir)
        torctl_writable = util.FileWritable(torctl_logpath)
        logging.info("Logging Tor {0} control port monitor output to {1}".format(name, torctl_logpath))

        time.sleep(5)

        torctl_events = [e for e in monitor.get_supported_torctl_events() if e not in ['DEBUG', 'INFO', 'NOTICE', 'WARN', 'ERR']]
        torctl_monitor = monitor.TorMonitor(control_port, torctl_writable, events=torctl_events)
        torctl_helper = threading.Thread(target=monitor.TorMonitor.run, name="torctl_{0}_helper".format(name), args=(torctl_monitor,))
        torctl_helper.start()
        self.threads.append(torctl_helper)

        if hs_port_mapping is not None:
            logging.info("Creating ephemeral hidden service...")
            with stem.control.Controller.from_port(port=control_port) as torctl:
                torctl.authenticate()
                response = torctl.create_ephemeral_hidden_service(hs_port_mapping, detached=True, await_publication=True)
                self.hs_service_id = response.service_id
                self.hs_control_port = control_port
                logging.info("Ephemeral hidden service is available at {0}.onion".format(response.service_id))

        return torctl_logpath

    def __get_ip_address(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]

    def __generate_index(self, docroot_path):
        root = etree.Element("files")
        filepaths = [f for f in os.listdir(docroot_path) if os.path.isfile(os.path.abspath('/'.join([docroot_path, f])))]
        for filename in filepaths:
            e = etree.SubElement(root, "file")
            e.set("name", filename)
        with open("{0}/index.xml".format(docroot_path), 'wb') as f: print >> f, etree.tostring(root, pretty_print=True, xml_declaration=True)

    def __get_download_count(self, tgen_logpath):
        count = 0
        if tgen_logpath is not None and os.path.exists(tgen_logpath):
            with open(tgen_logpath, 'r') as fin:
                for line in fin:
                    if re.search("transfer-complete", line) is not None:
                        count += 1
        return count

    def __is_alive(self):
        all_alive = True
        for t in self.threads:
            t_name = t.getName()
            if t.is_alive():
                logging.info("{0} is alive".format(t_name))
            else:
                logging.warning("{0} is dead!".format(t_name))
                all_alive = False
        return all_alive
