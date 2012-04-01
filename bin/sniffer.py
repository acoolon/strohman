import sys, os
import socket
import random

try: import strohman
except ImportError:
    sys.path.append(os.getcwd())

from strohman.net import netpacket
BUFSIZE = 1401


class Analizer:
    def __init__(self, name):
        self.monitor = name
        self.multi_queue = dict()

    def analize(self, data):
        if data is None: return
        packets = list()
        packet = netpacket.BasePacket(data)
        if packet.is_part:
            if packet.id in self.multi_queue:
                if self.multi_queue[packet.id].append(packet):
                    packet = self.multi_queue.pop(packet.id)
                    packets.append(packet)
            else: self.multi_queue[packet.id] = packet
        elif packet.is_multi:
            multi = list(netpacket.MultiPacket(data))
            packets.extend(multi)
        else: packets.append(packet)

        for packet in packets:
            packet = netpacket.by_type(packet.msg_type, packet)
            self.print_pretty(packet)

    def print_pretty(self, packet):
        packet.unpack_body()
        print('{} -> got:\t{}'.format(self.monitor, str(packet)))


class Connection:
    def __init__(self, ip_adress, port):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.settimeout(0)
        self.port = port
        self.ip_adress = ip_adress
        self.remote_port = 0
        self.remote_ip_adress = ''
        self.counter = 0
        self.monitor = 'unknown'
        self._bind()
        self.analizer = Analizer(self.monitor)

    def close(self):
        self.socket.close()

    def _read(self):
        try:
            (msg, (ip_adress, port)) = self.socket.recvfrom(BUFSIZE)
        except socket.error as s_error:
            if s_error.errno == 11:
                msg = ip_adress = port = None
            else: raise socket.error(s_error.errno)
        return (msg, ip_adress, port)

    def send(self, msg):
        if msg is not None:
            self.socket.sendto(msg, (self.ip_adress, self.port))

    def print_pretty(self, data):
        self.analizer.analize(data)
        #print('{} {} {}'.format(self.monitor, self.counter, data))
        #self.counter += 1


class Server(Connection):
    def _bind(self):
        self.socket.bind(('', random.randint(1025, 8000)))
        self.monitor = 'server'

    def receive(self):
        (msg, self.remote_ip_adress, self.remote_port) = self._read()
        if msg is not None:# and (ip == self.ip_adress, port == self.port):
            self.print_pretty(msg)
            return msg


class Client(Connection):
    def _bind(self):
        self.socket.bind((self.ip_adress, self.port))
        self.monitor = 'client'

    def receive(self):
        (msg, ip_adress, port) = self._read()
        if all((msg, ip_adress, port)):
            self.remote_ip_adress = self.ip_adress = ip_adress
            self.remote_port = self.port = port
            self.print_pretty(msg)
            return msg


def main(*args):
    server = Server('planeshift.subhosting.net', 7777)
    client = Client('localhost', 7776)

    try:
        while True:
            server.send(client.receive())
            client.send(server.receive())
    finally:
        server.close()
        client.close()

if __name__ == '__main__': main(*sys.argv[1:])
