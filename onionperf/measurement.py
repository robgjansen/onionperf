'''
  OnionPerf
  Authored by Rob Jansen
  See LICENSE for licensing information
'''

import os, subprocess, threading, Queue, logging, time, datetime, re, shlex
from lxml import etree

# stem imports
from stem.util import str_tools
from stem.control import Controller
from stem.version import Requirement, get_system_tor_version
from stem import __version__ as stem_version

# onionperf imports
import analysis, monitor, model, util

def generate_docroot_index(docroot_path):
    root = etree.Element("files")
    filepaths = [f for f in os.listdir(docroot_path) if os.path.isfile(os.path.abspath('/'.join([docroot_path, f])))]
    for filename in filepaths:
        e = etree.SubElement(root, "file")
        e.set("name", filename)
    with open("{0}/index.xml".format(docroot_path), 'wb') as f: print >> f, etree.tostring(root, pretty_print=True, xml_declaration=True)

def readline_thread_task(instream, q):
    # wait for lines from stdout until the EOF
    for line in iter(instream.readline, b''): q.put(line)

def watchdog_thread_task(cmd, cwd, writable, done_ev, send_stdin, ready_search_str, ready_ev):

    # launch or re-launch our sub process until we are told to stop
    while done_ev.is_set() is False:
        stdin_handle = subprocess.PIPE if send_stdin is not None else None
        subp = subprocess.Popen(shlex.split(cmd), cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=stdin_handle)

        # send some data to stdin if requested
        if send_stdin is not None:
            subp.stdin.write(send_stdin)
            subp.stdin.close()

        # wait for a string to appear in stdout if requested
        if ready_search_str is not None:
            boot_re = re.compile(ready_search_str)
            for line in iter(subp.stdout.readline, b''):
                writable.write(line)
                if boot_re.search(line):
                    break  # got it!

        # now the process is running *and* 'ready'
        if ready_ev is not None:
            ready_ev.set()

        # a helper will block on stdout and return lines back to us in a queue
        stdout_q = Queue.Queue()
        t = threading.Thread(target=readline_thread_task, args=(subp.stdout, stdout_q))
        t.start()

        # collect output from the helper and write it, continuously checking to make
        # sure that the subprocess is still alive and the master doesn't want us to quit
        while subp.poll() is None and done_ev.is_set() is False:
            try:
                # collect lines until the queue is empty for a full second
                while True:
                    line = stdout_q.get(True, 1)
                    writable.write(line)
            except Queue.Empty:
                # the queue is empty and the get() timed out, recheck loop conditions
                continue

        # either the process died, or we should shut down gracefully

        # if the process is still running, stop it
        if subp.poll() is None:
            # we collected no exit code, so it is still running
            subp.terminate()
            subp.wait()

        # the subp should be stopped now, flush any remaining lines
        subp.stdout.close()

        # the helper should stop since stdout was closed
        t.join()

        # helper thread is done, make sure we drain the remaining lines from the stdout queue
        while not stdout_q.empty():
            writable.write(stdout_q.get_nowait())
        # now loop around: either the master asked us to stop, or the subp died and we relaunch it

    # master asked us to stop, close the writable before exiting thread
    writable.close()

def logrotate_thread_task(writables, tgen_writable, torctl_writable, docroot, nickname, done_ev):
    next_midnight = None

    while not done_ev.wait(1):
        # get time
        utcnow = datetime.datetime.utcnow()

        # setup the next expiration time (midnight tonight)
        if next_midnight is None:
            next_midnight = datetime.datetime(utcnow.year, utcnow.month, utcnow.day, 23, 59, 59)
            # make sure we are not already past the above time today
            if (next_midnight - utcnow).total_seconds() < 0:
                next_midnight -= datetime.timedelta(1)  # subtract 1 day

        # if we are past midnight, launch the rotate task
        if (next_midnight - utcnow).total_seconds() < 0:
            # handle the general writables we are watching
            for w in writables:
                w.rotate_file()

            # handle tgen and tor writables specially, and do analysis
            if tgen_writable is not None or torctl_writable is not None:
                try:
                    # set up the analysis object with our log files
                    anal = analysis.Analysis(nickname=nickname)
                    if tgen_writable is not None:
                        anal.add_tgen_file(tgen_writable.rotate_file())
                    if torctl_writable is not None:
                        anal.add_torctl_file(torctl_writable.rotate_file())

                    # run the analysis, i.e. parse the files
                    anal.analyze(do_simple=False)

                    # save the results in onionperf and torperf format in the twistd docroot
                    anal_filename = "{0:04d}-{1:02d}-{2:02d}.onionperf.analysis.json.xz".format(next_midnight.year, next_midnight.month, next_midnight.day)
                    anal.save(filename=anal_filename, output_prefix=docroot, do_compress=True)
                    anal.export_torperf_version_1_0(output_prefix=docroot, datetimestamp=next_midnight, do_compress=False)

                    # update the xml index in docroot
                    generate_docroot_index(docroot)
                except Exception as e:
                    logging.warning("Caught and ignored exception in TorPerf log parser: {0}".format(repr(e)))

            # reset our timer
            next_midnight = None

class Measurement(object):

    def __init__(self, tor_bin_path, tgen_bin_path, twistd_bin_path, datadir_path, nickname):
        self.tor_bin_path = tor_bin_path
        self.tgen_bin_path = tgen_bin_path
        self.twistd_bin_path = twistd_bin_path
        self.datadir_path = datadir_path
        self.nickname = nickname
        self.threads = None
        self.done_event = None
        self.hs_service_id = None
        self.twisted_docroot = None

    def run(self, do_onion=True, do_inet=True, client_tgen_port=58888, client_tor_ctl_port=59050, client_tor_socks_port=59000,
             server_tgen_port=80, server_tor_ctl_port=59051, server_tor_socks_port=59001, twistd_port=50080):
        '''
        only `server_tgen_port` and `twistd_port` are "public" and need to be opened on the firewall.
        all ports need to be unique though, and unique among multiple onionperf instances.

        here are some sane defaults:
        client_tgen_port=58888, client_tor_ctl_port=59050, client_tor_socks_port=59000,
        server_tgen_port=80, server_tor_ctl_port=59051, server_tor_socks_port=59001, twistd_port=50080
        '''
        self.threads = []
        self.done_event = threading.Event()

        # if ctrl-c is pressed, shutdown child processes properly
        try:
            # make sure stem and Tor supports ephemeral HS (version >= 0.2.7.1-alpha)?
            if do_onion:
                try:
                    tor_version = get_system_tor_version(self.tor_bin_path)
                    if tor_version < Requirement.ADD_ONION:  # ADD_ONION is a stem 1.4.0 feature
                        logging.warning("OnionPerf in onion mode requires Tor version >= 0.2.7.1-alpha, you have {0}, aborting".format(tor_version))
                        return
                except:
                    logging.warning("OnionPerf in onion mode requires stem version >= 1.4.0, you have {0}, aborting".format(stem_version))
                    return

            logging.info("Bootstrapping started...")
            logging.info("Log files for the client and server processes will be placed in {0}".format(self.datadir_path))

            general_writables = []
            tgen_client_writable, torctl_client_writable = None, None

            if do_onion or do_inet:
                general_writables.append(self.__start_tgen_server(server_tgen_port))

            if do_onion:
                tor_writable, torctl_writable = self.__start_tor_server(server_tor_ctl_port, server_tor_socks_port)
                general_writables.append(tor_writable)
                general_writables.append(torctl_writable)

            if do_onion or do_inet:
                tor_writable, torctl_client_writable = self.__start_tor_client(client_tor_ctl_port, client_tor_socks_port)
                general_writables.append(tor_writable)

            server_urls = []
            if do_onion and self.hs_service_id is not None: server_urls.append("{0}.onion:{1}".format(self.hs_service_id, server_tgen_port))
            if do_inet: server_urls.append("{0}:{1}".format(util.get_ip_address(), server_tgen_port))

            if do_onion or do_inet:
                assert len(server_urls) > 0

                tgen_client_writable = self.__start_tgen_client(server_urls)
                general_writables.append(self.__start_twistd(twistd_port))

                self.__start_log_processors(general_writables, tgen_client_writable, torctl_client_writable)

                logging.info("Bootstrapping finished, entering heartbeat loop")
                time.sleep(1)
                broken_count = 0
                while True:
                    # TODO add status update of some kind? maybe the number of files in the twistd directory?
                    # logging.info("Heartbeat: {0} downloads have completed successfully".format(self.__get_download_count(tgen_client_writable.filename)))

                    while broken_count < 60:
                        if self.__is_alive():
                            logging.info("All helper processes seem to be alive :)")
                            broken_count = 0
                            break
                        else:
                            logging.warning("Some parallel components have died :(")
                            broken_count += 1
                            logging.info("Waiting 60 seconds for watchdog to reboot subprocess...")
                            time.sleep(60)

                    if broken_count >= 60:
                        logging.info("We've been in a broken state for 60 minutes, giving up and exiting now")
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
                try:
                    with Controller.from_port(port=self.hs_control_port) as torctl:
                        torctl.authenticate()
                        torctl.remove_ephemeral_hidden_service(self.hs_service_id)
                except: pass  # this fails to authenticate if tor proc is dead

#            logging.disable(logging.INFO)
            self.done_event.set()
            for t in self.threads:
                logging.info("Joining {0} thread...".format(t.getName()))
                t.join()
            time.sleep(1)
#            logging.disable(logging.NOTSET)

            logging.info("Child processes terminated")
            logging.info("Child process cleanup complete!")
            logging.info("Exiting")

    def __start_log_processors(self, general_writables, tgen_writable, torctl_writable):
        # rotate the log files, and then parse out the torperf measurement data
        logrotate_args = (general_writables, tgen_writable, torctl_writable, self.twisted_docroot, self.nickname, self.done_event)
        logrotate = threading.Thread(target=logrotate_thread_task, name="logrotate", args=logrotate_args)
        logrotate.start()
        self.threads.append(logrotate)

    def __start_tgen_client(self, server_urls, tgen_port, socks_port):
        return self.__start_tgen("client", tgen_port, socks_port, server_urls)

    def __start_tgen_server(self, tgen_port):
        return self.__start_tgen("server", tgen_port)

    def __start_tgen(self, name, tgen_port, socks_port=None, server_urls=None):
        logging.info("Starting TGen {0} process...".format(name))

        tgen_datadir = "{0}/tgen-{1}".format(self.datadir_path, name)
        if not os.path.exists(tgen_datadir): os.makedirs(tgen_datadir)

        tgen_confpath = "{0}/tgen.graphml.xml".format(tgen_datadir)
        if os.path.exists(tgen_confpath): os.remove(tgen_confpath)
        if socks_port is None:
            model.ListenModel(tgen_port="{0}".format(tgen_port)).dump_to_file(tgen_confpath)
            logging.info("TGen server running at 0.0.0.0:{0}".format(tgen_port))
        else:
            model.TorperfModel(tgen_port="{0}".format(tgen_port), tgen_servers=server_urls, socksproxy="127.0.0.1:{0}".format(socks_port)).dump_to_file(tgen_confpath)

        tgen_logpath = "{0}/onionperf.tgen.log".format(tgen_datadir)
        tgen_writable = util.FileWritable(tgen_logpath)
        logging.info("Logging TGen client process output to {0}".format(tgen_logpath))

        tgen_cmd = "{0} {1}".format(self.tgen_bin_path, tgen_confpath)
        tgen_args = (tgen_cmd, tgen_datadir, tgen_writable, self.done_event, None, None, None)
        tgen_watchdog = threading.Thread(target=watchdog_thread_task, name="tgen_{0}_watchdog".format(name), args=tgen_args)
        tgen_watchdog.start()
        self.threads.append(tgen_watchdog)

        return tgen_writable

    def __start_twistd(self, twistd_port):
        logging.info("Starting Twistd server process...")

        twisted_datadir = "{0}/twistd".format(self.datadir_path)
        if not os.path.exists(twisted_datadir): os.makedirs(twisted_datadir)

        twisted_logpath = "{0}/onionperf.twisted.log".format(twisted_datadir)
        twisted_writable = util.FileWritable(twisted_logpath)
        logging.info("Logging Twisted process output to {0}".format(twisted_logpath))

        twisted_docroot = "{0}/docroot".format(twisted_datadir)
        if not os.path.exists(twisted_docroot): os.makedirs(twisted_docroot)
        generate_docroot_index(twisted_docroot)
        self.twisted_docroot = twisted_docroot

        twisted_cmd = "{0} -n -l - web --port {1} --path {2} --mime-type=None".format(self.twistd_bin_path, twistd_port, twisted_docroot)
        twisted_args = (twisted_cmd, twisted_datadir, twisted_writable, self.done_event, None, None, None)
        twisted_watchdog = threading.Thread(target=watchdog_thread_task, name="twistd_watchdog", args=twisted_args)
        twisted_watchdog.start()
        self.threads.append(twisted_watchdog)
        logging.info("Twistd web server running at 0.0.0.0:{0}".format(twistd_port))

        return twisted_writable

    def __start_tor_client(self, control_port, socks_port):
        return self.__start_tor("client", control_port, socks_port)

    def __start_tor_server(self, control_port, socks_port, tgen_server_port):
        return self.__start_tor("server", control_port, socks_port, {tgen_server_port: tgen_server_port})

    def __start_tor(self, name, control_port, socks_port, hs_port_mapping=None):
        logging.info("Starting Tor {0} process...".format(name))

        tor_datadir = "{0}/tor-{1}".format(self.datadir_path, name)
        if not os.path.exists(tor_datadir): os.makedirs(tor_datadir)

        tor_config_template = "ORPort 0\nDirPort 0\nControlPort {0}\nSocksPort {1}\nSocksListenAddress 127.0.0.1\nClientOnly 1\n\
WarnUnsafeSocks 0\nSafeLogging 0\nMaxCircuitDirtiness 60 seconds\nUseEntryGuards 0\nDataDirectory {2}\nLog INFO stdout\n"
        tor_config = tor_config_template.format(control_port, socks_port, tor_datadir)

        tor_logpath = "{0}/onionperf.tor.log".format(tor_datadir)
        tor_writable = util.FileWritable(tor_logpath)
        logging.info("Logging Tor {0} process output to {1}".format(name, tor_logpath))

        # from stem.process import launch_tor_with_config
        # tor_subp = launch_tor_with_config(tor_config, tor_cmd=self.tor_bin_path, completion_percent=100, init_msg_handler=None, timeout=None, take_ownership=False)
        tor_cmd = "{0} -f -".format(self.tor_bin_path)
        tor_stdin_bytes = str_tools._to_bytes(tor_config)
        tor_ready_str = "Bootstrapped 100"
        tor_ready_ev = threading.Event()
        tor_args = (tor_cmd, tor_datadir, tor_writable, self.done_event, tor_stdin_bytes, tor_ready_str, tor_ready_ev)
        tor_watchdog = threading.Thread(target=watchdog_thread_task, name="tor_{0}_watchdog".format(name), args=tor_args)
        tor_watchdog.start()
        self.threads.append(tor_watchdog)

        # wait until Tor finishes bootstrapping
        tor_ready_ev.wait()

        torctl_logpath = "{0}/onionperf.torctl.log".format(tor_datadir)
        torctl_writable = util.FileWritable(torctl_logpath)
        logging.info("Logging Tor {0} control port monitor output to {1}".format(name, torctl_logpath))

        # give a few seconds to make sure Tor had time to start listening on the control port
        time.sleep(3)

        torctl_events = [e for e in monitor.get_supported_torctl_events() if e not in ['DEBUG', 'INFO', 'NOTICE', 'WARN', 'ERR']]
        torctl_args = (control_port, torctl_writable, torctl_events, self.done_event)
        torctl_helper = threading.Thread(target=monitor.tor_monitor_run, name="torctl_{0}_helper".format(name), args=torctl_args)
        torctl_helper.start()
        self.threads.append(torctl_helper)

        if hs_port_mapping is not None:
            logging.info("Creating ephemeral hidden service...")
            with Controller.from_port(port=control_port) as torctl:
                torctl.authenticate()
                response = torctl.create_ephemeral_hidden_service(hs_port_mapping, detached=True, await_publication=True)
                self.hs_service_id = response.service_id
                self.hs_control_port = control_port
                logging.info("Ephemeral hidden service is available at {0}.onion".format(response.service_id))

        return tor_writable, torctl_writable

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
