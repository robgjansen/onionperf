'''
Created on Oct 1, 2015

@author: rob
'''

import matplotlib; matplotlib.use('Agg')  # for systems without X11
from matplotlib.backends.backend_pdf import PdfPages
import pylab, numpy, time
from abc import abstractmethod

LINEFORMATS = "k-,r-,b-,g-,c-,m-,y-,k--,r--,b--,g--,c--,m--,y--,k:,r:,b:,g:,c:,m:,y:,k-.,r-.,b-.,g-.,c-., m-.,y-."
pylab.rcParams.update({
    'backend': 'PDF',
    'font.size': 16,
    'figure.max_num_figures' : 50,
    'figure.figsize': (6, 4.5),
    'figure.dpi': 100.0,
    'figure.subplot.left': 0.10,
    'figure.subplot.right': 0.95,
    'figure.subplot.bottom': 0.13,
    'figure.subplot.top': 0.92,
    'grid.color': '0.1',
    'axes.grid' : True,
    'axes.titlesize' : 'small',
    'axes.labelsize' : 'small',
    'axes.formatter.limits': (-4, 4),
    'xtick.labelsize' : 'small',
    'ytick.labelsize' : 'small',
    'lines.linewidth' : 2.0,
    'lines.markeredgewidth' : 0.5,
    'lines.markersize' : 10,
    'legend.fontsize' : 'x-small',
    'legend.fancybox' : False,
    'legend.shadow' : False,
    'legend.ncol' : 1.0,
    'legend.borderaxespad' : 0.5,
    'legend.numpoints' : 1,
    'legend.handletextpad' : 0.5,
    'legend.handlelength' : 1.6,
    'legend.labelspacing' : .75,
    'legend.markerscale' : 1.0,
    'ps.useafm' : True,
    'pdf.use14corefonts' : True,
    # 'text.usetex' : True,
})

class Visualization(object):

    def __init__(self):
        self.datasets = []

    def add_dataset(self, analysis, label, lineformat):
        self.datasets.append((analysis, label, lineformat))

    @abstractmethod
    def plot_all(self, output_prefix):
        pass

class TorVisualization(Visualization):

    def plot_all(self, output_prefix):
        if len(self.datasets) > 0:
            prefix = output_prefix + '.' if output_prefix is not None else ''
            ts = time.strftime("%Y-%m-%d_%H:%M:%S")
            self.page = PdfPages("{0}tor.onionperf.viz.{1}.pdf".format(prefix, ts))
            self.__plot_bytes(direction="bytes_read")
            self.__plot_bytes(direction="bytes_written")
            self.page.close()

    def __plot_bytes(self, direction="bytes_written"):
        mafig = pylab.figure()
        allcdffig = pylab.figure()
        eachcdffig = pylab.figure()

        for (anal, label, lineformat) in self.datasets:
            assert anal.result is not None and 'nodes' in anal.result
            d = anal.result['nodes']
            tput = {}
            pertput = []
            for node in d:
                if 'relay' not in node and 'thority' not in node: continue
                for tstr in d[node][direction]:
                    mib = d[node][direction][tstr] / 1048576.0
                    t = int(tstr)
                    if t not in tput: tput[t] = 0
                    tput[t] += mib
                    pertput.append(mib)

            pylab.figure(mafig.number)
            x = sorted(tput.keys())
            y = [tput[t] for t in x]
            y_ma = movingaverage(y, 60)
            pylab.scatter(x, y, s=0.1)
            pylab.plot(x, y_ma, lineformat, label=label)

            pylab.figure(allcdffig.number)
            x, y = getcdf(y)
            pylab.plot(x, y, lineformat, label=label)

            pylab.figure(eachcdffig.number)
            x, y = getcdf(pertput)
            pylab.plot(x, y, lineformat, label=label)

        pylab.figure(mafig.number)
        pylab.xlabel("Tick (s)")
        pylab.ylabel("Throughput (MiB/s)")
        pylab.xlim(xmin=0.0)
        pylab.ylim(ymin=0.0)
        pylab.title("60 second moving average throughput, {0}, all relays".format("write" if direction == "bytes_written" else "read"))
        pylab.legend(loc="lower right")
        self.page.savefig()
        pylab.close()
        del(mafig)

        pylab.figure(allcdffig.number)
        pylab.xlabel("Throughput (MiB/s)")
        pylab.ylabel("Cumulative Fraction")
        pylab.title("1 second throughput, {0}, all relays".format("write" if direction == "bytes_written" else "read"))
        pylab.legend(loc="lower right")
        self.page.savefig()
        pylab.close()
        del(allcdffig)

        pylab.figure(eachcdffig.number)
        # pylab.xscale('log')
        pylab.xlabel("Throughput (MiB/s)")
        pylab.ylabel("Cumulative Fraction")
        pylab.title("1 second throughput, {0}, each relay".format("write" if direction == "bytes_written" else "read"))
        pylab.legend(loc="lower right")
        self.page.savefig()
        pylab.close()
        del(eachcdffig)

class TGenVisualization(Visualization):

    def plot_all(self, output_prefix):
        if len(self.datasets) > 0:
            prefix = output_prefix + '.' if output_prefix is not None else ''
            ts = time.strftime("%Y-%m-%d_%H:%M:%S")
            self.page = PdfPages("{0}tgen.onionperf.viz.{1}.pdf".format(prefix, ts))
            self.__plot_firstbyte()
            self.__plot_lastbyte_all()
            self.__plot_lastbyte_median()
            self.__plot_lastbyte_mean()
            self.__plot_lastbyte_max()
            self.__plot_downloads()
            self.__plot_errors()
            self.__plot_errsizes_all()
            self.__plot_errsizes_median()
            self.__plot_errsizes_mean()
            self.page.close()

    def __plot_firstbyte(self):
        f = None

        for (anal, label, lineformat) in self.datasets:
            assert anal.result is not None and 'nodes' in anal.result
            d = anal.result['nodes']
            fb = []
            for client in d:
                if "firstbyte" in d[client]:
                    for b in d[client]["firstbyte"]:
                        if f is None: f = pylab.figure()
                        for sec in d[client]["firstbyte"][b]: fb.extend(d[client]["firstbyte"][b][sec])
            if f is not None and len(fb) > 0:
                x, y = getcdf(fb)
                pylab.plot(x, y, lineformat, label=label)

        if f is not None:
            pylab.xlabel("Download Time (s)")
            pylab.ylabel("Cumulative Fraction")
            pylab.title("time to download first byte, all clients")
            pylab.legend(loc="lower right")
            self.page.savefig()
            pylab.close()

    def __plot_lastbyte_all(self):
        figs = {}

        for (anal, label, lineformat) in self.datasets:
            assert anal.result is not None and 'nodes' in anal.result
            d = anal.result['nodes']
            lb = {}
            for client in d:
                if "lastbyte" in d[client]:
                    for b in d[client]["lastbyte"]:
                        bytes = int(b)
                        if bytes not in figs: figs[bytes] = pylab.figure()
                        if bytes not in lb: lb[bytes] = []
                        for sec in d[client]["lastbyte"][b]: lb[bytes].extend(d[client]["lastbyte"][b][sec])
            for bytes in lb:
                x, y = getcdf(lb[bytes])
                pylab.figure(figs[bytes].number)
                pylab.plot(x, y, lineformat, label=label)

        for bytes in sorted(figs.keys()):
            pylab.figure(figs[bytes].number)
            pylab.xlabel("Download Time (s)")
            pylab.ylabel("Cumulative Fraction")
            pylab.title("time to download {0} bytes, all downloads".format(bytes))
            pylab.legend(loc="lower right")
            self.page.savefig()
            pylab.close()

    def __plot_lastbyte_median(self):
        figs = {}

        for (anal, label, lineformat) in self.datasets:
            assert anal.result is not None and 'nodes' in anal.result
            d = anal.result['nodes']
            lb = {}
            for client in d:
                if "lastbyte" in d[client]:
                    for b in d[client]["lastbyte"]:
                        bytes = int(b)
                        if bytes not in figs: figs[bytes] = pylab.figure()
                        if bytes not in lb: lb[bytes] = []
                        client_lb_list = []
                        for sec in d[client]["lastbyte"][b]: client_lb_list.extend(d[client]["lastbyte"][b][sec])
                        lb[bytes].append(numpy.median(client_lb_list))
            for bytes in lb:
                x, y = getcdf(lb[bytes])
                pylab.figure(figs[bytes].number)
                pylab.plot(x, y, lineformat, label=label)

        for bytes in sorted(figs.keys()):
            pylab.figure(figs[bytes].number)
            pylab.xlabel("Download Time (s)")
            pylab.ylabel("Cumulative Fraction")
            pylab.title("median time to download {0} bytes, each client".format(bytes))
            pylab.legend(loc="lower right")
            self.page.savefig()
            pylab.close()

    def __plot_lastbyte_mean(self):
        figs = {}

        for (anal, label, lineformat) in self.datasets:
            assert anal.result is not None and 'nodes' in anal.result
            d = anal.result['nodes']
            lb = {}
            for client in d:
                if "lastbyte" in d[client]:
                    for b in d[client]["lastbyte"]:
                        bytes = int(b)
                        if bytes not in figs: figs[bytes] = pylab.figure()
                        if bytes not in lb: lb[bytes] = []
                        client_lb_list = []
                        for sec in d[client]["lastbyte"][b]: client_lb_list.extend(d[client]["lastbyte"][b][sec])
                        lb[bytes].append(numpy.mean(client_lb_list))
            for bytes in lb:
                x, y = getcdf(lb[bytes])
                pylab.figure(figs[bytes].number)
                pylab.plot(x, y, lineformat, label=label)

        for bytes in sorted(figs.keys()):
            pylab.figure(figs[bytes].number)
            pylab.xlabel("Download Time (s)")
            pylab.ylabel("Cumulative Fraction")
            pylab.title("mean time to download {0} bytes, each client".format(bytes))
            pylab.legend(loc="lower right")
            self.page.savefig()
            pylab.close()

    def __plot_lastbyte_max(self):
        figs = {}

        for (anal, label, lineformat) in self.datasets:
            assert anal.result is not None and 'nodes' in anal.result
            d = anal.result['nodes']
            lb = {}
            for client in d:
                if "lastbyte" in d[client]:
                    for b in d[client]["lastbyte"]:
                        bytes = int(b)
                        if bytes not in figs: figs[bytes] = pylab.figure()
                        if bytes not in lb: lb[bytes] = []
                        client_lb_list = []
                        for sec in d[client]["lastbyte"][b]: client_lb_list.extend(d[client]["lastbyte"][b][sec])
                        lb[bytes].append(numpy.max(client_lb_list))
            for bytes in lb:
                x, y = getcdf(lb[bytes])
                pylab.figure(figs[bytes].number)
                pylab.plot(x, y, lineformat, label=label)

        for bytes in sorted(figs.keys()):
            pylab.figure(figs[bytes].number)
            pylab.xlabel("Download Time (s)")
            pylab.ylabel("Cumulative Fraction")
            pylab.title("max time to download {0} bytes, each client".format(bytes))
            pylab.legend(loc="lower right")
            self.page.savefig()
            pylab.close()

    def __plot_downloads(self):
        figs = {}

        for (anal, label, lineformat) in self.datasets:
            assert anal.result is not None and 'nodes' in anal.result
            d = anal.result['nodes']
            dls = {}
            for client in d:
                if "lastbyte" in d[client]:
                    for b in d[client]["lastbyte"]:
                        bytes = int(b)
                        if bytes not in figs: figs[bytes] = pylab.figure()
                        if bytes not in dls: dls[bytes] = {}
                        if client not in dls[bytes]: dls[bytes][client] = 0
                        for sec in d[client]["lastbyte"][b]: dls[bytes][client] += len(d[client]["lastbyte"][b][sec])
            for bytes in dls:
                x, y = getcdf(dls[bytes].values(), shownpercentile=1.0)
                pylab.figure(figs[bytes].number)
                pylab.plot(x, y, lineformat, label=label)

        for bytes in sorted(figs.keys()):
            pylab.figure(figs[bytes].number)
            pylab.xlabel("Downloads Completed (\#)")
            pylab.ylabel("Cumulative Fraction")
            pylab.title("number of {0} byte downloads completed, each client".format(bytes))
            pylab.legend(loc="lower right")
            self.page.savefig()
            pylab.close()

    def __plot_errors(self):
        figs = {}

        for (anal, label, lineformat) in self.datasets:
            assert anal.result is not None and 'nodes' in anal.result
            d = anal.result['nodes']
            dls = {}
            for client in d:
                if "errors" in d[client]:
                    for code in d[client]["errors"]:
                        if code not in figs: figs[code] = pylab.figure()
                        if code not in dls: dls[code] = {}
                        if client not in dls[code]: dls[code][client] = 0
                        for sec in d[client]["errors"][code]: dls[code][client] += len(d[client]["errors"][code][sec])
            for code in dls:
                x, y = getcdf([dls[code][client] for client in dls[code]], shownpercentile=1.0)
                pylab.figure(figs[code].number)
                pylab.plot(x, y, lineformat, label=label)

        for code in sorted(figs.keys()):
            pylab.figure(figs[code].number)
            pylab.xlabel("Download Errors (\#)")
            pylab.ylabel("Cumulative Fraction")
            pylab.title("number of transfer {0} errors, each client".format(code))
            pylab.legend(loc="lower right")
            self.page.savefig()
            pylab.close()

    def __plot_errsizes_all(self):
        figs = {}

        for (anal, label, lineformat) in self.datasets:
            assert anal.result is not None and 'nodes' in anal.result
            d = anal.result['nodes']
            err = {}
            for client in d:
                if "errors" in d[client]:
                    for code in d[client]["errors"]:
                        if code not in figs: figs[code] = pylab.figure()
                        if code not in err: err[code] = []
                        client_err_list = []
                        for sec in d[client]["errors"][code]: client_err_list.extend(d[client]["errors"][code][sec])
                        for b in client_err_list: err[code].append(int(b) / 1024.0)
            for code in err:
                x, y = getcdf(err[code])
                pylab.figure(figs[code].number)
                pylab.plot(x, y, lineformat, label=label)

        for code in sorted(figs.keys()):
            pylab.figure(figs[code].number)
            pylab.xlabel("Data Transferred (KiB)")
            pylab.ylabel("Cumulative Fraction")
            pylab.title("bytes transferred before {0} error, all downloads".format(code))
            pylab.legend(loc="lower right")
            self.page.savefig()
            pylab.close()

    def __plot_errsizes_median(self):
        figs = {}

        for (anal, label, lineformat) in self.datasets:
            assert anal.result is not None and 'nodes' in anal.result
            d = anal.result['nodes']
            err = {}
            for client in d:
                if "errors" in d[client]:
                    for code in d[client]["errors"]:
                        if code not in figs: figs[code] = pylab.figure()
                        if code not in err: err[code] = []
                        client_err_list = []
                        for sec in d[client]["errors"][code]: client_err_list.extend(d[client]["errors"][code][sec])
                        err[code].append(numpy.median(client_err_list) / 1024.0)
            for code in err:
                x, y = getcdf(err[code])
                pylab.figure(figs[code].number)
                pylab.plot(x, y, lineformat, label=label)

        for code in sorted(figs.keys()):
            pylab.figure(figs[code].number)
            pylab.xlabel("Data Transferred (KiB)")
            pylab.ylabel("Cumulative Fraction")
            pylab.title("median bytes transferred before {0} error, each client".format(code))
            pylab.legend(loc="lower right")
            self.page.savefig()
            pylab.close()

    def __plot_errsizes_mean(self):
        figs = {}

        for (anal, label, lineformat) in self.datasets:
            assert anal.result is not None and 'nodes' in anal.result
            d = anal.result['nodes']
            err = {}
            for client in d:
                if "errors" in d[client]:
                    for code in d[client]["errors"]:
                        if code not in figs: figs[code] = pylab.figure()
                        if code not in err: err[code] = []
                        client_err_list = []
                        for sec in d[client]["errors"][code]: client_err_list.extend(d[client]["errors"][code][sec])
                        err[code].append(numpy.mean(client_err_list) / 1024.0)
            for code in err:
                x, y = getcdf(err[code])
                pylab.figure(figs[code].number)
                pylab.plot(x, y, lineformat, label=label)

        for code in sorted(figs.keys()):
            pylab.figure(figs[code].number)
            pylab.xlabel("Data Transferred (KiB)")
            pylab.ylabel("Cumulative Fraction")
            pylab.title("mean bytes transferred before {0} error, each client".format(code))
            pylab.legend(loc="lower right")
            self.page.savefig()
            pylab.close()

class OnionPerfVisualization(object):

    def __init__(self, params):
        page = PdfPages("onionperf.results.{0}.pdf".format(time.strftime("%Y-%m-%d_%H:%M:%S")))
        self.plot(params, page)
        self.page.close()

    def plot(self, args, page):
        colors = {51200:'r', 1048576:'b', 5242880:'g'}
        hours = {}

        # first byte, time series
        d = {}
        for bytes in args.results['firstbyte']:
            for (ts, t) in args.results['firstbyte'][bytes]: d[ts] = t

        pylab.figure()

        keys = sorted(d.keys())
        num_hours = (keys[-1] - keys[0]) / 3600.0
        x = [(k - keys[0]) / 3600.0 for k in keys]
        y = [d[k] for k in keys]

        for i in x:
            if int(i) not in hours: hours[int(i)] = True

        y_ma = movingaverage(y, int(num_hours / 10.0))
        pylab.scatter(x, y, c='k', linewidths=0, s=3.0, alpha=0.5, label='raw')
        pylab.plot(x, y_ma, 'r-', label='smoothed')

        pylab.xlabel("Time Span (h)")
        pylab.xlim(xmin=0, xmax=num_hours)
        pylab.ylabel("Download Time (s)")
        pylab.ylim(ymin=0, ymax=10.0)
        pylab.title("OnionPerf: time to download first byte")
        pylab.legend(loc="best")
        page.savefig()
        pylab.close()

        # first byte, cdf
        d = {}
        for bytes in args.results['firstbyte']:
            if bytes not in [51200, 1048576, 5242880]: continue
            if bytes not in d: d[bytes] = {}
            for (ts, t) in args.results['firstbyte'][bytes]: d[bytes][ts] = t

        pylab.figure()

        maxx = 0
        for bytes in d:
            keys = sorted(d[bytes].keys())
            num_hours = (keys[-1] - keys[0]) / 3600.0
            vals = [d[bytes][k] for k in keys]
            x, y = getcdf(vals)
            pylab.plot(x, y, '-', c=colors[bytes], label="{0} KiB".format(int(bytes / 1024.0)))
            if x[-1] > maxx: maxx = x[-1]

        pylab.xlabel("Download Time (s)")
        pylab.xlim(xmin=0, xmax=maxx)
        pylab.ylabel("Cumulative Fraction")
        pylab.ylim(ymin=0, ymax=1.0)
        pylab.title("OnionPerf: time to download first byte")
        pylab.legend(loc="lower right")
        page.savefig()
        pylab.close()

        # last byte, time series
        d = {}
        for bytes in args.results['lastbyte']:
            if bytes not in [51200, 1048576, 5242880]: continue
            if bytes not in d: d[bytes] = {}
            for (ts, t) in args.results['lastbyte'][bytes]: d[bytes][ts] = t

        pylab.figure()

        for bytes in d:
            keys = sorted(d[bytes].keys())
            num_hours = (keys[-1] - keys[0]) / 3600.0
            x = [(k - keys[0]) / 3600.0 for k in keys]
            y = [d[bytes][k] for k in keys]

            y_ma = movingaverage(y, int(num_hours / 10.0))
            pylab.scatter(x, y, c=colors[bytes], edgecolor=colors[bytes], linewidths=0, s=3.0, alpha=0.5)
            pylab.plot(x, y_ma, '-', c=colors[bytes], label="{0} KiB".format(int(bytes / 1024.0)))

        pylab.xlabel("Time Span (h)")
        pylab.xlim(xmin=0, xmax=num_hours)
        pylab.ylabel("Download Time (s)")
        pylab.ylim(ymin=0, ymax=60.0)
        pylab.title("OnionPerf: time to download last byte")
        pylab.legend(loc="best")
        page.savefig()
        pylab.close()

        # last byte, cdf
        pylab.figure()

        maxx = 0
        for bytes in d:
            keys = sorted(d[bytes].keys())
            num_hours = (keys[-1] - keys[0]) / 3600.0
            vals = [d[bytes][k] for k in keys]
            x, y = getcdf(vals)
            pylab.plot(x, y, '-', c=colors[bytes], label="{0} KiB".format(int(bytes / 1024.0)))
            if x[-1] > maxx: maxx = x[-1]

        pylab.xlabel("Download Time (s)")
        pylab.xlim(xmin=0, xmax=maxx)
        pylab.ylabel("Cumulative Fraction")
        pylab.ylim(ymin=0, ymax=1.0)
        pylab.title("OnionPerf: time to download last byte")
        pylab.legend(loc="lower right")
        page.savefig()
        pylab.close()

        # errors, time series
        d = {51200:{}, 1048576:{}, 5242880:{}}
        for h in hours:
            for b in d: d[b][int(h)] = 0

        mints = None
        for code in args.results['errors']:
            for (ts, bytes) in args.results['errors'][code]:
                if bytes not in d: continue
                if mints == None: mints = ts
                h = int((ts - mints) / 3600.0)
                d[bytes][h] += 1

        pylab.figure()

        maxy = 1
        for bytes in d:
            x = sorted(d[bytes].keys())
            y = [d[bytes][k] for k in x]
            if max(y) > maxy: maxy = max(y)
            pylab.scatter(x, y, c=colors[bytes], edgecolor=colors[bytes], s=10.0, label="{0} KiB".format(int(bytes / 1024.0)))

        pylab.xlabel("Time Span (h)")
        pylab.xlim(xmin=0, xmax=num_hours)
        pylab.ylabel("Number of Errors Per Hour")
        pylab.ylim(ymin=0, ymax=maxy)
        pylab.title("OnionPerf: number of errors")
        pylab.legend(loc="best")
        page.savefig()
        pylab.close()

# helper - compute the window_size moving average over the data in interval
def movingaverage(interval, window_size):
    window = numpy.ones(int(window_size)) / float(window_size)
    return numpy.convolve(interval, window, 'same')

# # helper - cumulative fraction for y axis
def cf(d): return pylab.arange(1.0, float(len(d)) + 1.0) / float(len(d))

# # helper - return step-based CDF x and y values
# # only show to the 99th percentile by default
def getcdf(data, shownpercentile=0.99, maxpoints=10000.0):
    data.sort()
    frac = cf(data)
    k = len(data) / maxpoints
    x, y, lasty = [], [], 0.0
    for i in xrange(int(round(len(data) * shownpercentile))):
        if i % k > 1.0: continue
        assert not numpy.isnan(data[i])
        x.append(data[i])
        y.append(lasty)
        x.append(data[i])
        y.append(frac[i])
        lasty = frac[i]
    return x, y
