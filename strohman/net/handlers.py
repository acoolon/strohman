import time
import random
import hashlib
import logging

from strohman.net import netpacket


LOGGER = logging.getLogger(__name__)


class BaseHandler:
    def __init__(self, interface):
        self.logger = LOGGER.getChild(self.__class__.__name__)
        self.interface = interface
        self.registered = dict()

    def __str__(self): return self.__class__.__name__

    def register(self, packet, handler, times=0):
        '''
        Register a handler for the packet.
        times specifies how many packets are passed. 0 means infinite.
        If the number exceeds the packets are dropped.
        '''
        if packet not in self.registered:
            self.interface.connection.packet_handler.register(self, packet)
        self.registered[packet] = (handler, 0, times)

    def close(self):
        for packet in self.registered:
            self.interface.connection.packet_handler.unregister(self, packet)

    def get_handler(self, packet):
        for p in self.registered:
            if isinstance(packet, p):
                (handler, passed, maximum) = self.registered[p]
                if maximum != 0 and passed > maximum:
                    string = 'Called {} already {} times, dropping packet.'
                    self.logger.warning(string.format(self, passed))
                    return False
                else:
                    passed += 1
                    self.registered[p] = (handler, passed, maximum)
                    return handler

    def handle(self, packet):
        handler = self.get_handler(packet)
        if callable(handler):
            packet.unpack_body()
            handler(packet)
        elif handler is None:
            self.logger.warning('{} handler got unhandled {}'.format(self,
                                                                     packet))


class Vitals(BaseHandler):
    def __init__(self, interface):
        super().__init__(interface)
        self.register(netpacket.AckPacket, self.handle_ack)
        self.register(netpacket.HeartbeatPacket, self.handle_heartbeat)
        self.register(netpacket.SystemPacket, self.handle_system)
        #  This is not used by the server.
        #self.register(netpacket.AuthrejectedPacket, self.handle_disconnect)
        self.register(netpacket.DisconnectPacket, self.handle_disconnect)

    def handle_disconnect(self, packet):
        self.logger.info('Exited with reason >{}<.'.format(packet.reason))
        self.interface.on_disconnect(self)

    def handle_ack(self, packet): self.logger.debug(str(packet))
    def handle_heartbeat(self, packet): pass
    def handle_system(self, packet):
        self.logger.info(str(packet))
        self.interface.on_system_msg(self, packet.msg.strip())


class Disconnect(BaseHandler):
    def __init__(self, interface):
        super().__init__(interface)
 #       self.register(netpacket.DisconnectPacket, self.handle_disconnect)
        if self.interface.connection.push(netpacket.DisconnectPacket()):
            self.logger.info('Exiting...')

#    def handle_disconnect(self, packet):
#        self.logger.info('Exited gracefully >{}<.'.format(packet.reason))
#        self.interface.on_disconnect(self)


class Ping(BaseHandler):
    def __init__(self, interface):
        super().__init__(interface)
        self.register(netpacket.PingPacket, self.handle_ping)
        self.delay = self.lastping = 0
        self.event = None
        self.is_up = False
        self.ping()

    def __str__(self):
        if self.is_up: return 'Server up: {}ms.'.format(self.delay)
        else: return 'Server down.'

    def close(self):
        super().close()
        self.cancel_timeout()

    def ping(self):
        self.lastping = time.time()
        self.event = self.interface.sched.enter(3, 1,
                                                self.handle_timeout,
                                                tuple())
        packet = netpacket.PingPacket(payload=random.randint(1, 3000))
        if self.interface.connection.push(packet):
            self.logger.info('Sent a ping to the server.')

    def cancel_timeout(self):
        if not self.event is None:
            self.interface.sched.cancel(self.event)
            self.event = None

    def handle_ping(self, packet):
        if packet.flags == 6: self.is_up = True
        elif packet.flags in (10, 0): self.is_up = False
        self.delay = int((time.time() - self.lastping) * 1000)
        self.cancel_timeout()
        self.logger.info(str(self))
        self.interface.on_ping(self, self.is_up, self.delay)

    def handle_timeout(self):
        self.is_up = False
        self.delay = 9999
        self.event = None
        self.logger.info(str(self))
        self.interface.on_ping(self, self.is_up, self.delay)


class Authenticate(BaseHandler):
    def __init__(self, interface, username, password):
        super().__init__(interface)
        self.register(netpacket.PreAuthapprovedPacket, self.handle_pre, 1)
        self.register(netpacket.AuthapprovedPacket, self.handle_app, 1)
        self.register(netpacket.DisconnectPacket, self.handle_disconnect, 1)
        self.username = username
        self.password = password
        if self.interface.connection.push(netpacket.PreauthenticatePacket()):
            self.logger.info('Sent initial preauth')

    def handle_pre(self, packet):
        auth = netpacket.AuthenticatePacket()
        auth.username = self.username
        pw = '{0}:{1}'.format(self.password, packet.clientnum)
        auth.password = hashlib.md5(pw.encode('utf-8')).hexdigest()
        auth.os = 'Unix-x86-GCC'
        auth.gfxcard = 'Homegrown'
        auth.gfxversion = 'Homegrown'
        if self.interface.connection.push(auth):
            self.logger.info('Sent authenticate (username: {0}, password: {1})'.format(
                                self.username, self.password))

    def handle_app(self, packet):
        chars = [char[0] for char in packet.chars]
        self.logger.info('Got {0}.'.format(', '.join(chars)))
        self.interface.on_auth_done(self, packet.chars)

    def handle_disconnect(self, packet):
        self.logger.info('Login failed: {0}'.format(packet.reason))
        self.interface.on_auth_failed(self)


class Login(BaseHandler):
    def __init__(self, interface, char_name):
        super().__init__(interface)
        self.register(netpacket.AuthCharacterApprovedPacket, self.handle_authchar, 1)
        self.register(netpacket.PersistWorldPacket, self.handle_world, 1)
        if self.interface.connection.push(netpacket.AuthCharacterPacket(char_name=char_name)):
            self.logger.info('Logging in with {0}'.format(char_name))

    def handle_authchar(self, packet):
        self.logger.info('Logged in.')
        # After this the server places the char into the world
        self.interface.connection.push(netpacket.PersistWorldRequestPacket())

    def handle_world(self, packet):
        if self.interface.connection.push(netpacket.ClientStatusPacket()):
            self.logger.info('Char is at the map {}, sending client READY'.format(packet.sector))
            self.interface.on_login(self)


class Weather(BaseHandler):
    def __init__(self, interface):
        super().__init__(interface)
        self.register(netpacket.WeatherPacket, self.handle_weather)
        self.last_date = {'minute': 0, 'hour': 0, 'day': 0, 'month': 0, 'year': 0}
        self.weather_map = dict()

    def handle_weather(self, packet):
        self.logger.info(str(packet))
        if packet.date:
            self.last_date = packet.date
            self.interface.on_weather_timeup(self, self.last_date)
        elif packet.sector:
            self.weather_map[packet.sector] = (packet.downfall, packet.fog)
            self.interface.on_weather_weatherup(self,
                                                packet.sector,
                                                self.weather_map[packet.sector])


class Chat(BaseHandler):
    def __init__(self, interface):
        super().__init__(interface)
        self.register(netpacket.ChatPacket, self.handle_chat)
        self.register(netpacket.ChannelJoinedPacket, self.handle_joined)
        self.flood_protect = None
        self.channel_names = dict()
        self.channel_numbers = dict()

    def join_channel(self, name):
        self.interface.connection.push(netpacket.ChannelJoinPacket(name=name))

    def leave_channel(self, name):
        channel = self.channel_names[recipient]
        leave = netpacket.ChannelLeavePacket(channel_id=channel)
        if self.interface.connection.push(leave):
            self.logger.info('Leaving channel {}'.format(name))

    def send_chat(self, ctype, recipient, text):
        if recipient + text != self.flood_protect:
            if ctype == netpacket.ChatPacket.CHANNEL:
                # XXX keyerror
                channel = self.channel_names[recipient]
                self.interface.connection.push(netpacket.ChatPacket(chat_type=ctype,
                                                    text=text, channel_id=channel))
            else:
                self.interface.connection.push(netpacket.ChatPacket(chat_type=ctype,
                                                    text=text, recipient=recipient))
            self.flood_protect = recipient + text
        else: self.logger.warn('Chat: Not sending {} to {}'.format(text, recipient))

    def handle_joined(self, packet):
        self.channel_names[packet.name] = packet.channel_id
        self.channel_numbers[packet.channel_id] = packet.name
        self.logger.info('Joined channel {}.'.format(packet.name))

    def handle_chat(self, packet):
        if self.interface.actor_handler.get_my_name().startswith(packet.recipient):
            self.logger.warn('Discarding chat {}'.format(packet))
            return  # chat by me - discard
        self.logger.info(str(packet))
        if packet.chat_type == packet.SYSTEM:
            self.interface.on_chat_system(self, packet.recipient, packet.text)
        elif packet.chat_type == packet.COMBAT:
            self.interface.on_chat_combat(self, packet.recipient, packet.text)
        elif packet.chat_type == packet.SAY:
            self.interface.on_chat_say(self, packet.recipient, packet.text)
        elif packet.chat_type == packet.TELL:
            self.interface.on_chat_tell(self, packet.recipient, packet.text)
        elif packet.chat_type == packet.GROUP:
            self.interface.on_chat_group(self, packet.recipient, packet.text)
        elif packet.chat_type == packet.GUILD:
            self.interface.on_chat_guild(self, packet.recipient, packet.text)
        elif packet.chat_type == packet.ALLIANCE:
            self.interface.on_chat_alliance(self, packet.recipient, packet.text)
        elif packet.chat_type == packet.AUCTION:
            self.interface.on_chat_auction(self, packet.recipient, packet.text)
        elif packet.chat_type == packet.SHOUT:
            self.interface.on_chat_shout(self, packet.recipient, packet.text)
        elif packet.chat_type == packet.CHANNEL:
            self.interface.on_chat_channel(self, packet.recipient, packet.text,
                                        self.channel_numbers[packet.channel_id])
        elif packet.chat_type == packet.TELLSELF:
            self.interface.on_chat_tellself(self, packet.recipient, packet.text)
        elif packet.chat_type == packet.REPORT:
            self.interface.on_chat_report(self, packet.recipient, packet.text)
        elif packet.chat_type == packet.ADVISOR:
            self.interface.on_chat_advisor(self, packet.recipient, packet.text)
        elif packet.chat_type == packet.ADVICE:
            self.interface.on_chat_advice(self, packet.recipient, packet.text)
        elif packet.chat_type == packet.ADVICE_LIST:
            self.interface.on_chat_advice_list(self, packet.recipient, packet.text)
        elif packet.chat_type == packet.SERVER_TELL:
            self.interface.on_chat_sever_tell(self, packet.recipient, packet.text)
        elif packet.chat_type == packet.GM:
            self.interface.on_chat_gm(self, packet.recipient, packet.text)
        elif packet.chat_type == packet.SERVER_INFO:
            self.interface.on_chat_server_info(self, packet.recipient, packet.text)
        elif packet.chat_type == packet.NPC:
            self.interface.on_chat_npc(self, packet.recipient, packet.text)
        elif packet.chat_type == packet.SYSTEM_BASE:
            self.interface.on_chat_system_base(self, packet.recipient, packet.text)
        elif packet.chat_type == packet.PET_ACTION:
            self.interface.on_chat_pet_action(self, packet.recipient, packet.text)
        elif packet.chat_type == packet.NPC_ME:
            self.interface.on_chat_npc_me(self, packet.recipient, packet.text)
        elif packet.chat_type == packet.NPC_MY:
            self.interface.on_chat_npc_my(self, packet.recipient, packet.text)
        elif packet.chat_type == packet.NPC_NARRATE:
            self.interface.on_chat_(npc_narrateself, packet.recipient, packet.text)
        elif packet.chat_type == packet.AWAY:
            self.interface.on_chat_away(self, packet.recipient, packet.text)
        elif packet.chat_type == packet.END:
            self.interface.on_chat_end(self, packet.recipient, packet.text)
        else:
            self.logger.warn('Unknown chat: ' + str(packet))


class Command(BaseHandler):
    def __init__(self, interface):
        super().__init__(interface)

    def user_cmd(self, cmd):
        if self.interface.connection.push(netpacket.UserCmdPacket(command=cmd)):
            LOGGER.info('Sent user command: {}'.format(cmd))



class Actors(BaseHandler):
    def __init__(self, interface):
        super().__init__(interface)
        self.register(netpacket.PersistActorPacket, self.handle_actor)
        self.register(netpacket.DeadReckoningPacket, self.handle_dr)
        self.register(netpacket.RemoveObjectPacket, self.handle_rmobj)
        self.register(netpacket.StatDRUpdatePacket, self.handle_statdr)
        self.interface.connection.push(netpacket.PersistActorRequestPacket())
        self.actors = dict()
        self.my_id = None

    def get_my_name(self):
        if not self.my_id is None:
            return self.actors[self.my_id]['name']

    def handle_actor(self, packet):
        if packet.counter == 0: self.my_id = packet.entity_id
        self.actors[packet.entity_id] = {'pos': packet.pos, 'drcounter':
                                         packet.counter, 'name': packet.name}
        self.interface.on_actor_new(self, packet.entity_id)

    def handle_dr(self, packet):
        if not packet.entity_id in self.actors:
            self.logger.error('DR for unregistered Actor: {}'.format(packet.entity_id))
            self.actors[packet.entity_id] = {'name': '', 'drcounter': -1}
        actor = self.actors[packet.entity_id]
        if actor['drcounter'] < packet.counter:
            actor['pos'] = packet.pos
            actor['drcounter'] = packet.counter
            self.interface.on_actor_moved(self, packet.entity_id)

    def handle_rmobj(self, packet):
        if packet.entity_id in self.actors:
            actor = self.actors.pop(packet.entity_id)
            logging.info('Removed Actor: {} - {}'.format(actor['name'],
                                                         packet.entity_id))
            self.interface.on_actor_del(self, packet.entity_id)
        else:
            self.logger.error('No such Actor: {}'.format(packet.entity_id))

    def handle_statdr(self, packet):
        if not packet.entity_id in self.actors:
            self.logger.error('StatDR for unregistered Actor: {}'.format(packet.entity_id))
        #    self.actors[packet.entity_id] = {'name': '', 'statcounter': -1}
        else:
            actor = self.actors[packet.entity_id]
            self.logger.info('StatDR for: {}'.format(actor['name']))
