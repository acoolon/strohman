import socket
import random

import pcap
import select
import time


from strohman.net import netpacket


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


class SocketConnection(asynsocket.dispatcher):
    def __init__(self, mgr, port, remote_ip='', remote_port=9999):
        super().__init__()
        self.create_socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.bind(('locahost', port))
        self.bind((ip, port))
        self.mgr = mgr
        self.remote_ip = remote_ip
        eself.remote_port = remote_port
        self.out_buffer = list()

    def readable(self): return True
    def writable(self): return bool(self.out_buffer)
    def handle_close(self): self.close()
    def handle_error(self): print('Exception')

    def handle_write(self):
        self.sendto(self.out_buffer.pop(0),
                    (self.remote_ip, self.remote_port))

    def handle_read(self):
        (msg, (self.remote_ip, self.remote_port)) = self.socket.recvfrom(1400)
        mgr.handle_read(msg, self.remote_ip)


class SocketSniffer:
    def __init__(self, server_ip, server_port, client_port):
        self.server = SocketConnection(self, random.randint(1025, 8000),
                                       server_ip, server_port)
        self.client = SocketConnection(self, client_port)
        self.server_analizer = Analizer('server')
        self.client_analizer = Analizer('client')
        self.server_ip = server_ip

    def handle_read(self, data, ip):
        if ip == self.server_ip:
            self.server_analizer.analize(data)
            self.server.out_buffer.append(data)
        else:
            self.client.analize(data)
            self.client.out_buffer.append(data)

    def close(self):
        self.server.close()
        self.client.close()


class NeedToBeRoot(UserWarning): pass


class Sniffer(object):
    def __init__(self, ip=config.SNIFFER_IP, port=config.SNIFFER_PORT,
                 timeout=config.SNIFFER_TIMEOUT, device=config.SNIFFER_DEVICE):
        self.pcap = pcap.pcapObject()
        try:
            if device is '': device = pcap.lookupdev()
        except Exception as e: raise NeedToBeRoot(str(e))
        try:
            self.pcap.open_live(device, 65535, 0, 100)
        except Exception as e: raise NeedToBeRoot(str(e))
        filter_string = 'dst {} and port {} and udp'
        self.pcap.setfilter(filter_string.format(ip, port), 0, 0)
        self.pcap.setnonblock(1)

        self.closed = False # ugly
        self.timeout = timeout
        self.epoll = select.epoll()
        self.epoll.register(self.pcap.fileno(), select.EPOLLIN)

    def __iter__(self):
        return self

    def _pcap_generator(self):
        rec = self.pcap.next()
        while rec:
            yield rec
            rec = self.pcap.next()

    def next(self):
        if self.closed: raise StopIteration()
        timeout = time.time() + self.timeout
        nto = round(timeout - time.time(), 3)

        while nto > 0.001:
            if self.epoll.poll(nto):
                for (num, data, tstamp) in reversed(tuple(self._pcap_generator())):
                    packet = Packet(data, tstamp)
                    if packet.is_valid: return packet
            else: time.sleep(0.001)
            nto = round(timeout - time.time(), 3)
        return None

    def close(self):
        self.epoll.close()
        self.closed = True
