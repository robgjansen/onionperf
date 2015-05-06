#!/usr/bin/python
import sys, os, argparse
from subprocess import Popen, PIPE

DESCRIPTION="""
A utility to help analyze onionperf output. Currently, this parses tgen transfer complete messages, and plots the results.
"""

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
            if len(parts) < 3 or parts[2].find('.') < 0: continue
            # check for our log line types
            if 'transfer-complete' in parts[4] or 'transfer-error' in parts[4]: tgen_parse(args, parts)
        except: continue
    if 'xzproc' in args: args.xzproc.wait()

def tgen_parse(args, parts):
    ioparts = parts[11].split('=')
    iodirection = ioparts[0]
    if 'read' not in iodirection: return

    bytes = int(ioparts[1].split('/')[0])

    if results not in args: args.results = {'firstbyte':{}, 'lastbyte':{}, 'errors':{}}

    if 'transfer-complete' in parts[4]:
        cmdtime = int(parts[13].split('=')[1])/1000.0
        rsptime = int(parts[14].split('=')[1])/1000.0
        fbtime = int(parts[15].split('=')[1])/1000.0
        lbtime = int(parts[16].split('=')[1])/1000.0
        chktime = int(parts[17].split('=')[1])/1000.0

        if bytes not in args.results['firstbyte']: args.results['firstbyte'][bytes] = []
        args.results['firstbyte'][bytes].append(fbtime-cmdtime)

        if bytes not in args.results['lastbyte']: args.results['lastbyte'][bytes] = []
        args.results['lastbyte'][bytes].append(lbtime-cmdtime)

    elif 'transfer-error' in parts[4]:
        code = parts[8].strip('()').split('-')[7].split('=')[1]

        if code not in args.results['errors']: args.results['errors'][code] = []
        args.results['errors'][code].append(bytes)

if __name__ == '__main__': sys.exit(main())
