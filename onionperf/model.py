'''
Created on Oct 1, 2015

@author: robgjansen
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
        g.add_node("transfer50k", type="get", protocol="tcp", size="50 KiB")
        g.add_node("transfer1m", type="get", protocol="tcp", size="1 MiB")
        g.add_node("transfer5m", type="get", protocol="tcp", size="5 MiB")

        g.add_edge("start", "pause")
        g.add_edge("pause", "choose")
        g.add_edge("pause", "pause")
        g.add_edge("choose", "transfer50k")
        g.add_edge("choose", "transfer1m")
        g.add_edge("choose", "transfer5m")

        return g
