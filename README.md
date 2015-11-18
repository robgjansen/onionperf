# OnionPerf

OnionPerf is a utility to track Tor and onion service performance.

OnionPerf uses multiple processes and threads to download random data
through Tor while tracking the performance of those downloads. The data is
served and fetched on localhost using two TGen (traffic generator)
processes, and is transferred through Tor using Tor client processes and
an ephemeral Tor Onion Service. Tor control information and TGen
performance statistics are logged to disk, analyzed once per day to
produce a json stats database and files that can feek into Torperf, and
can later be used to visualize changes in Tor client performance over time.

For more information, see https://github.com/robgjansen/onionperf.

### Install Dependencies

  + **Tor** (>= v0.2.7.1-alpha): libevent, openssl
  + **TGen** (Shadow >= v1.11.0): cmake, glib2, igraph
  + **OnionPerf**: python, python modules: stem (>= v1.4.0), twisted, lxml, networkx, numpy, matplotlib.

Fedora/RedHat:

```
sudo yum install gcc cmake make glib2 glib2-devel igraph igraph-devel libevent libevent-devel openssl openssl-devel 
sudo yum install python python-stem python-twisted python-lxml python-networkx python-matplotlib numpy scipy
```

Ubuntu/Debian:

```
sudo apt-get install gcc cmake make libglib2.0 libglib2.0-dev libigraph0 libigraph0-dev libevent libevent-dev openssl openssl-dev
sudo apt-get install python python-stem python-twisted python-lxml python-networkx python-matplotlib python-numpy python-scipy
```

Python modules can be installed with `pip` if you satisfy the requirements of the module. The module requirements for each OnionPerf subcommand are as follows:

  + `onionperf monitor`: stem
  + `onionperf model`: networkx
  + `onionperf measure`: stem, lxml, twisted, networkx
  + `onionperf analyze`: stem
  + `onionperf visualize`: scipy, numpy, pylab, matplotlib

**Note**: You may want to skip installing numpy and matplotlib if you don't plan to use the visualize subcommand, since those tend to require several large dependencies.

**Note**: You can install Tor via the package manager as well, though the preferred method is to build from source.

### Build Tor

```
git clone
configure
make
```

### Build TGen Traffic Generator

The traffic generator currently exists in the Shadow simulator repository,
but we will build TGen as an external tool and skip building both the full 
simulator and the TGen simulator plugin.

```
git clone https://github.com/shadow/shadow.git
cd shadow/src/plugin/shadow-plugin-tgen
mkdir build
cd build
cmake .. -DSKIP_SHADOW=ON -DCMAKE_MODULE_PATH=`pwd`/../../../../cmake/
make
```

### Prepare OnionPerf


http://docs.python-guide.org/en/latest/dev/virtualenvs/

### Run OnionPerf

You will need to give onionperf the path to your custom 'tor' and 'tgen'
binary files if they do not exist in your PATH environment variable.

```
git clone https://github.com/robgjansen/onionperf.git
cd onionperf
./onionperf -h
./onionperf --tor=/home/rob/tor/src/or/tor --tgen=/home/rob/shadow/src/plugin/shadow-plugin-tgen/build/tgen
```

This will store all local state, including log files, to the `.onionperf`
directory. Let it run, and by default it will download files over Tor every
60 minutes, and log the results.

### Analyze Results

You can run the client tgen log file through `onionperf-analyze.py` to
visualize changes in performance over time.

```
python onionperf-analyze.py .onionperf/client/tgen/tgen.log
```

This will save a new PDF in the current directory.


### Implementation Notes

OnionPerf has two timers to be aware of:

The **heartbeat timer** runs in the main process. Once configuration is complete, the main process loops through the following:
  1. parse the tgen log file and count the number of completed downloads,
  1. check that all helper processes are alive,
  1. sleep for 3600 seconds,
  1. repeat.

The **download timer** runs in the tgen client download manager child process. The download manager:
  1. downloads files by cycling through the file sizes (default sizes are 50 KiB, 1 MiB, and 5 MiB) until it attempts `burst_num` total downloads,
  1. pauses for `burst_interval` seconds.

Both `burst_num` and `burst_interval` are adjustable flags to OnionPerf and are listed in the help menu (`onionperf --help`).

### Contribute

GitHub pull requests are welcome and encouraged!
