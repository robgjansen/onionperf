#!/usr/bin/python

import matplotlib; matplotlib.use('Agg') # for systems without X11
from matplotlib.backends.backend_pdf import PdfPages
import sys, os, argparse, pylab, numpy, time
from subprocess import Popen, PIPE

DESCRIPTION="""
A utility to help analyze onionperf output. Currently, this parses tgen transfer complete messages, and plots the results to a PDF file that is saved in the current directory.
"""

pylab.rcParams.update({
    'backend': 'PDF',
    'font.size': 16,
    'figure.max_num_figures' : 50,
    'figure.figsize': (6,4.5),
    'figure.dpi': 100.0,
    'figure.subplot.left': 0.10,
    'figure.subplot.right': 0.95,
    'figure.subplot.bottom': 0.13,
    'figure.subplot.top': 0.92,
    'grid.color': '0.1',
    'axes.grid' : True,
    'axes.titlesize' : 'small',
    'axes.labelsize' : 'small',
    'axes.formatter.limits': (-4,4),
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
#    'text.usetex' : True,
})

def main():
    parser = argparse.ArgumentParser(
        description=DESCRIPTION,
        formatter_class=argparse.RawTextHelpFormatter)

    parser.add_argument(
        help="""The PATH to the shadow.log file, which may be '-'for STDIN, or may end in '.xz' to enable inline xz decompression""",
        metavar="PATH",
        action="store", dest="logpath")

    args = parser.parse_args()
    args.logpath = os.path.abspath(os.path.expanduser(args.logpath))

    if args.logpath.endswith("-"):
        args.datasource = sys.stdin
    elif args.logpath.endswith(".xz"):
        args.xzproc = Popen(["xz", "--decompress", "--stdout", args.logpath], stdout=PIPE)
        args.datasource = args.xzproc.stdout
    else: args.datasource = open(args.logpath, 'r')

    for line in args.datasource:
        try:
            parts = line.strip('\n').split(' ')
            parse(args, parts)
        except: continue
    if 'xzproc' in args: args.xzproc.wait()

    page = PdfPages("onionperf.results.{0}.pdf".format(time.strftime("%Y-%m-%d_%H:%M:%S")))
    plot(args, page)
    page.close()

def parse(args, parts):
    if len(parts) < 19: return
    if 'transfer-complete' not in parts[5] and 'transfer-error' not in parts[5]: return

    ioparts = parts[12].split('=')
    iodirection = ioparts[0]
    if 'read' not in iodirection: return

    tstamp = float(parts[2])
    bytes = int(ioparts[1].split('/')[0])

    if 'results' not in args: args.results = {'firstbyte':{}, 'lastbyte':{}, 'errors':{}}

    if 'transfer-complete' in parts[5]:
        cmdtime = int(parts[14].split('=')[1])/1000.0
        rsptime = int(parts[15].split('=')[1])/1000.0
        fbtime = int(parts[16].split('=')[1])/1000.0
        lbtime = int(parts[17].split('=')[1])/1000.0
        chktime = int(parts[18].split('=')[1])/1000.0

        if bytes not in args.results['firstbyte']: args.results['firstbyte'][bytes] = []
        args.results['firstbyte'][bytes].append((tstamp, fbtime-cmdtime))

        if bytes not in args.results['lastbyte']: args.results['lastbyte'][bytes] = []
        args.results['lastbyte'][bytes].append((tstamp, lbtime-cmdtime))

    elif 'transfer-error' in parts[5]:
        code = parts[9].strip('()').split('-')[7].split('=')[1]

        if code not in args.results['errors']: args.results['errors'][code] = []
        args.results['errors'][code].append((tstamp, bytes))

def plot(args, page):
    colors = {51200:'r', 1048576:'b', 5242880:'g'}
    hours = {}

    # first byte, time series
    d = {}
    for bytes in args.results['firstbyte']:
        for (ts, t) in args.results['firstbyte'][bytes]: d[ts] = t

    pylab.figure()

    keys = sorted(d.keys())
    num_hours = (keys[-1]-keys[0])/3600.0
    x = [(k - keys[0])/3600.0 for k in keys]
    y = [d[k] for k in keys]

    for i in x:
        if int(i) not in hours: hours[int(i)] = True

    y_ma = movingaverage(y, int(num_hours/10.0))
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
        num_hours = (keys[-1]-keys[0])/3600.0
        vals = [d[bytes][k] for k in keys]
        x, y = getcdf(vals)
        pylab.plot(x, y, '-', c=colors[bytes], label="{0} KiB".format(int(bytes/1024.0)))
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
        num_hours = (keys[-1]-keys[0])/3600.0
        x = [(k - keys[0])/3600.0 for k in keys]
        y = [d[bytes][k] for k in keys]

        y_ma = movingaverage(y, int(num_hours/10.0))
        pylab.scatter(x, y, c=colors[bytes], edgecolor=colors[bytes], linewidths=0, s=3.0, alpha=0.5)
        pylab.plot(x, y_ma, '-', c=colors[bytes], label="{0} KiB".format(int(bytes/1024.0)))

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
        num_hours = (keys[-1]-keys[0])/3600.0
        vals = [d[bytes][k] for k in keys]
        x, y = getcdf(vals)
        pylab.plot(x, y, '-', c=colors[bytes], label="{0} KiB".format(int(bytes/1024.0)))
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
            h = int((ts-mints)/3600.0)
            d[bytes][h] += 1

    pylab.figure()

    maxy = 1
    for bytes in d:
        x = sorted(d[bytes].keys())
        y = [d[bytes][k] for k in x]
        if max(y) > maxy: maxy = max(y)
        pylab.scatter(x, y, c=colors[bytes], edgecolor=colors[bytes], s=10.0, label="{0} KiB".format(int(bytes/1024.0)))

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
    window = numpy.ones(int(window_size))/float(window_size)
    return numpy.convolve(interval, window, 'same')

## helper - cumulative fraction for y axis
def cf(d): return pylab.arange(1.0,float(len(d))+1.0)/float(len(d))

## helper - return step-based CDF x and y values
## only show to the 99th percentile by default
def getcdf(data, shownpercentile=0.99, maxpoints=10000.0):
    data.sort()
    frac = cf(data)
    k = len(data)/maxpoints
    x, y, lasty = [], [], 0.0
    for i in xrange(int(round(len(data)*shownpercentile))):
        if i % k > 1.0: continue
        assert not numpy.isnan(data[i])
        x.append(data[i])
        y.append(lasty)
        x.append(data[i])
        y.append(frac[i])
        lasty = frac[i]
    return x, y

if __name__ == '__main__': sys.exit(main())
