import socket
import errno
import logging

from strohman import asynsocket
from strohman.net import handlers
from strohman.net import netpacket


LOGGER = logging.getLogger(__name__)
MAX_PACKET_SIZE = 1400
HEARTBEAT_TIMEOUT = 30
TOTAL_TIMEOUT = 40


class PacketHandler:
    def __init__(self):
        self.logger = LOGGER.getChild(self.__class__.__name__)
        self.handlers = dict()
        self.fallback_handler = handlers.BaseHandler(None)

    def close(self):
        for handler in self.gen_handlers(): handler.close()
        if self.gen_handlers():
            self.logger.error('There are still some handlers registered.')

    def gen_handlers(self):
        registered_handlers = set(())
        for handlers in self.handlers.values():
            registered_handlers.update(handlers)
        return registered_handlers

    def distribute(self, packet):
        handlers = self.handlers.get(packet.msg_type,
                                     set((self.fallback_handler,)))
        for handler in handlers.copy(): handler.handle(packet)

    def register(self, handler, packet):
        msg_type = netpacket.message_type.index(packet)
        if msg_type in self.handlers: self.handlers[msg_type].add(handler)
        else: self.handlers[msg_type] = set((handler,))

    def unregister(self, handler, packet):
        msg_type = netpacket.message_type.index(packet)
        if msg_type in self.handlers:
            handlers = self.handlers.pop(msg_type)
            if handler in handlers: handlers.remove(handler)
            if handlers: self.handlers[msg_type] = handlers


class Connection:
    def __init__(self, interface, ip, port):
        self.logger = LOGGER.getChild(self.__class__.__name__)
        self.interface = interface
        self.connected = True
        self.asyn = self.packet_handler = self.heartbeat_gen = None
        self.asyn = Asynsocket(self, ip, port)
        self.packet_handler = PacketHandler()
        self.heartbeat_gen = self.heartbeat_generator(interface.sched)

    def close(self):
        if self.connected:
            self.connected = False
            self.logger.info('Closing connection.')
            if not self.heartbeat_gen is None: self.heartbeat_gen.close()
            if not self.packet_handler is None: self.packet_handler.close()
            if not self.asyn is None: self.asyn.close()

    def handle_error(self, reason):
        if self.connected:
            self.logger.error('Connection Error: {}'.format(reason))
            self.close()
            self.interface.on_connection_error()

    def handle_packet(self, *packets):
        next(self.heartbeat_gen)
        for packet in packets:
            self.packet_handler.distribute(packet)

    def push(self, packet):
        if self.connected:
            return self.asyn.push(packet)
        return False

    def heartbeat_generator(self, scheduler):
        def handle_hb():
            self.logger.error('Timeout, sending Heartbeat')
            self.push(netpacket.HeartbeatPacket())

        def handle_to():
            self.logger.error('Timeout, starting error handling.')
            self.handle_error('timeout')

        while True:
            heartbeat_event = scheduler.enter(HEARTBEAT_TIMEOUT, 1,
                                              handle_hb, tuple())
            timeout_event = scheduler.enter(TOTAL_TIMEOUT, 2,
                                            handle_to, tuple())
            try: yield
            finally:
                if heartbeat_event in scheduler.queue:
                    scheduler.cancel(heartbeat_event)
                if timeout_event in scheduler.queue:
                    scheduler.cancel(timeout_event)


class Asynsocket(asynsocket.dispatcher):
    def __init__(self, connection, ip, port):
        super().__init__()
        self.logger = LOGGER.getChild(self.__class__.__name__)
        self.id_counter = 1
        self.multi_queue = dict()
        self.out_buffer = list()
        self.connection = connection
        self.create_socket(socket.AF_INET, socket.SOCK_DGRAM)
        try: self.connect((ip, port))
        except IOError as e: self.handle_connection_error(e)

    def readable(self): return True
    def writable(self): return bool(self.out_buffer)
    def handle_close(self): self.close()
    def handle_error(self): self.logger.exception('Exc:')

    def handle_connection_error(self, error):
        self.logger.error('Catched error: {} (errno: {})'.format(error.strerror,
                                                                 error.errno))
        if error.errno in (socket.EAI_NONAME,
                           socket.EAI_AGAIN,
                           errno.ECONNREFUSED):
            self.close()
            self.connection.handle_error(error.strerror)

        elif error.errno in (errno.EINVAL, # unable to send
                            ):
            pass #XXX resend packet

    def handle_read(self):
        try: data = self.recv(MAX_PACKET_SIZE)
        except IOError as e: self.handle_connection_error(e)
        else:
            packet = netpacket.BasePacket(data)
            if packet.needs_ack: self.push(packet.ack())
            if packet.is_part: self.handle_part(packet)
            elif packet.is_multi: self.handle_multi(data)
            else:
                packet = netpacket.by_type(packet.msg_type, packet)
                self.logger.debug('Got {0}'.format(packet))
                self.connection.handle_packet(packet)

    def handle_part(self, packet):
        if packet.id in self.multi_queue:
            if self.multi_queue[packet.id].append(packet):
                packet = self.multi_queue.pop(packet.id)
                self.logger.debug('Multipart ({0}) completed: {1}'.format(packet.id, packet))
                self.connection.handle_packet(packet)
        else:
            self.logger.debug('Multipart {0} initiated.'.format(packet.id))
            packet = netpacket.by_type(packet.msg_type, packet)
            self.multi_queue[packet.id] = packet

    def handle_multi(self, data):
        multi = [netpacket.by_type(p.msg_type, p) for p in netpacket.MultiPacket(data)]
        self.logger.debug('Multipacket containing {0} packets:'.format(len(multi)))
        for (num, packet) in enumerate(multi):
            self.logger.debug('{0}\t{1}'.format(num, packet))
        self.connection.handle_packet(*multi)

    def handle_write(self):
        try:
            self.send(self.out_buffer.pop(0))
            return True
        except IOError as e:
            self.handle_connection_error(e)
            return False

    def push(self, packet):
        self.id_counter += 1
        packet.id = self.id_counter
        self.out_buffer.append(packet.pack())
        self.logger.debug('Send {0}'.format(packet))
