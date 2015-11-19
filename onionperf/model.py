'''
  OnionPerf
  Authored by Rob Jansen, 2015
  See LICENSE for licensing information
'''

from abc import ABCMeta, abstractmethod
from cStringIO import StringIO
from networkx import read_graphml, write_graphml, DiGraph

class TGenModel(object):
    '''
    an action-dependency graph model for Shadow's traffic generator
    '''

    __metaclass__ = ABCMeta

    def dump_to_string(self):
        s = StringIO()
        write_graphml(self.graph, s)
        return s.getvalue()

    def dump_to_file(self, filename):
        write_graphml(self.graph, filename)

class TGenLoadableModel(TGenModel):

    def __init__(self, graph):
        self.graph = graph

    @classmethod
    def from_file(cls, filename):
        graph = read_graphml(filename)
        model_instance = cls(graph)
        return model_instance

    @classmethod
    def from_string(cls, string):
        s = StringIO()
        s.write(string)
        graph = read_graphml(s)
        model_instance = cls(graph)
        return model_instance

class GeneratableTGenModel(TGenModel):

    __metaclass__ = ABCMeta

    @abstractmethod
    def generate(self):
        pass

class ListenModel(GeneratableTGenModel):

    def __init__(self, tgen_port="8888"):
        self.tgen_port = tgen_port
        self.graph = self.generate()

    def generate(self):
        g = DiGraph()
        g.add_node("start", serverport=self.tgen_port, loglevel="info", heartbeat="1 minute")
        return g

class TorperfModel(GeneratableTGenModel):

    def __init__(self, tgen_port="8889", tgen_servers=["127.0.0.1:8888"], socksproxy=None):
        self.tgen_port = tgen_port
        self.tgen_servers = tgen_servers
        self.socksproxy = socksproxy
        self.graph = self.generate()

    def generate(self):
        server_str = ','.join(self.tgen_servers)
        g = DiGraph()

        g.add_node("start", serverport=self.tgen_port, peers=server_str, loglevel="info", heartbeat="1 minute")
        if self.socksproxy is not None:
            g.node["start"]["socksproxy"] = self.socksproxy
        g.add_node("pause", time="5 minutes")
        g.add_node("choose")
        g.add_node("transfer50k", type="get", protocol="tcp", size="50 KiB", timeout="295 seconds", stallout="300 seconds")
        g.add_node("transfer1m", type="get", protocol="tcp", size="1 MiB", timeout="1795 seconds", stallout="1800 seconds")
        g.add_node("transfer5m", type="get", protocol="tcp", size="5 MiB", timeout="3595 seconds", stallout="3600 seconds")

        g.add_edge("start", "pause")

        # after the pause, we start another pause timer while *at the same time* choosing one of
        # the file sizes and downloading it from one of the servers in the server pool
        g.add_edge("pause", "choose")
        g.add_edge("pause", "pause")

        # these are chosen with equal probability unless a 'weight' attribute is set on the edges
        g.add_edge("choose", "transfer50k")
        g.add_edge("choose", "transfer1m")
        g.add_edge("choose", "transfer5m")

        return g

def dump_example_tgen_torperf_model(domain_name, onion_name):                                                                                                                        
    # the server listens on 8888, the client uses Tor to come back directly, and using a hidden serv
    server = ListenModel(tgen_port="8888")
    public_server_str = "{0}:8888".format(domain_name)
    onion_server_str = "{0}:8890".format(onion_name)
    client = TorperfModel(tgen_port="8889", socksproxy="localhost:9001", tgen_servers=[public_server_str, onion_server_str])
    
    # save to specified paths
    server.dump_to_file("tgen.server.torperf.graphml.xml")
    client.dump_to_file("tgen.client.torperf.graphml.xml")

