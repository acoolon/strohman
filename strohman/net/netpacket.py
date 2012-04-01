import struct


NET_VERSION = 185


class Data:
    def __init__(self, data=None):
        if isinstance(data, bytes) and data:
            self.data = data[:3]
            self.get_type()
            self.data = data
        else:
            self.type = self.size = 0
            self.data = b''
        self.debug_copy = self.data

    def __str__(self): return str(self.data)
    def __len__(self): return len(self.data) + 3
    def __bool__(self): return bool(self.data)
    def __add__(self, packet): return self.data + packet.data
    def __iadd__(self, packet):
        self.data += packet.data
        return self

    def _get(self, pattern):
        size = struct.calcsize(pattern)
        try: (data,) = struct.unpack(pattern, self.data[:size])
        except struct.error:
            raise RuntimeError('Unable to unpack {}.'.format(self.debug_copy))
        else:
            self.data = self.data[size:]
            return data

    def purge(self): self.data = b''
    def get_type(self):
        self.type = self.get_8()
        self.size = self.get_16()

    def get_data(self):
        size = len(self.data)
        return struct.pack('<BH', self.type, size) + self.data

    def put_32(self, data): self.data += struct.pack('<L', data)
    def get_32(self): return self._get('<L')

    def put_16(self, data): self.data += struct.pack('<H', data)
    def get_16(self): return self._get('<H')

    def put_8(self, data): self.data += struct.pack('<B', data)
    def get_8(self): return self._get('<B')

    def put_f(self, data): self.data += struct.pack('<f', float(data))
    def get_f(self): return self._get('<f')

    def put_vector(self, data):
        for fl in data: self.put_f(fl)
    def get_vector(self): return (self.get_f(), self.get_f(), self.get_f())

    def put_string(self, string): self.data += string.encode('utf-8') + b'\x00'
    def get_string(self):
        (string, self.data) = self.data.split(b'\x00', 1)
        try: return string.decode('utf-8')
        except UnicodeDecodeError: return 'UnicodeDecodeError'


class BasePacket:
    def __init__(self, packet=None, **kwargs):
        self.id = self.offset = self.priority = 0
        self.size = self.size_minor = self.msg_type = 0
        self.is_part = False
        self.needs_ack = False

        self._init()
        self.__dict__.update(kwargs)
        if isinstance(packet, bytes):
            self.data = Data(packet[15:])
            self.unpack_header(packet[:15])
        elif isinstance(packet, BasePacket):
            self.id = packet.id
            self.offset = packet.offset
            self.priority = packet.priority
            self.size = packet.size
            self.size_minor = packet.size_minor
            self.msg_type = packet.msg_type
            self.is_part = packet.is_multi
            self.needs_ack = packet.needs_ack
            self.data = packet.data
        else: self.data = Data()

    def __eq__(self, packet):
        return self.msg_type == packet.msg_type and \
            any((self.id == packet.id,
            self.offset == packet.offset,
            self.priority == packet.priority,
            self.size == packet.size))

    def __str__(self):
        string = self.__class__.__name__ + \
                '{} (ID: {},  Offset: {}, Priority {}, Size {}, MinorSize {})'
        _string = self._str().replace('\n', '\\n')
        string = string.format(_string, self.id, self.offset,
            self.priority, self.size, self.size_minor)
        if self.data.data != b'': string += ' --'
        return string

    def append(self, packet):
        if self.id == packet.id and self.size == packet.size:
            self.data += packet.data
            self.size_minor += packet.size_minor
            if self.size == self.size_minor:  # lets consider this as completed
                self.is_part = False
                self.data.get_type()
                return True

    def ack(self):
        if self.size == 0: self.pack()  # to obtain correct self.size
        ack = AckPacket()
        ack.packet_ack = self.id
        ack.offset = self.offset
        ack.priority = self.priority
        ack.sum = self.size
        return ack

    def pack(self):
        self.data.type = self.msg_type
        self.priority = 1 if self.needs_ack else self.priority
        self._pack()
        self.size = len(self.data)
        data = struct.pack('<LLLHB', self.id, self.offset,
                self.size, self.size, self.priority)
        return data + self.data.get_data()

    def unpack_header(self, data):
        (self.id,
         self.offset,
         self.size,
         self.size_minor,
         self.priority) = struct.unpack('<LLLHB', data)
        self.msg_type = self.data.type
        self.is_part = self.size != self.size_minor \
                and self.size_minor != 0
        self.is_multi = self.priority > 1
        self.needs_ack = self.priority > 0
        if self.data and not self.is_part:
            self.data.get_type()  # if not ack/part

    def unpack_body(self):
        if len(self.data) == self.size:
            self._unpack()

    def _init(self): pass
    def _unpack(self): pass
    def _pack(self): pass
    def _str(self): return ' ' + str(self.data.data)


def MultiPacket(data):
    data = data[15:]
    while data:
        (size,) = struct.unpack('<xxxxxxxxLxxx', data[:15])
        packet = data[:15 + size]
        data = data[15 + size:]
        yield BasePacket(packet)

#########################################


def by_type(msg_type, packet):
    try: return message_type[msg_type](packet)
    except IndexError: raise IndexError('No such Packet {}'.format(msg_type))

#########################################


class AckPacket(BasePacket):
    def _init(self):
        self.msg_type = 0
        self.packet_ack = self.sum = 0

    def _str(self):
        return ' ' + str(self.packet_ack)

    def pack(self):
        self.data.purge()
        self.is_part = self.needs_ack = False
        data = struct.pack('<LLLHB', self.packet_ack, self.offset,
                self.sum, 0, 0)
        return data

    def unpack_body(self):
        self.is_part = self.needs_ack = False
        self.packet_ack = self.id
        self.sum = self.size


class PingPacket(BasePacket):
    def _init(self):
        self.msg_type = 1
        self.payload = 0
        self.flags = 3

    def _str(self):
        return ' {}, flags: {}'.format(self.payload, self.flags)

    def _pack(self):
        self.data.purge()
        self.id = self.id or self.payload
        self.data.put_32(self.payload)
        self.data.put_8(self.flags)

    def _unpack(self):
        self.payload = self.data.get_32()
        self.flags = self.data.get_8()


class AuthenticatePacket(BasePacket):
    def _init(self):
        self.id = 2
        self.msg_type = 2
        self.version = NET_VERSION
        self.username = self.password = self.os = ''  # undefined
        self.gfxcard = self.gfxversion = ''  # undefined
        self.needs_ack = True

    def _str(self):
        string = ' username: {}, password: {}, os: {}, gfxcard: {}, gfxversion: {}'
        return string.format(self.username, self.password, self.os, self.gfxcard, self.gfxversion)

    def _pack(self):
        self.data.purge()
        self.data.put_32(NET_VERSION)
        for item in (self.username, self.password, self.os,
                self.gfxcard, self.gfxversion):
            self.data.put_string(item)


class PreauthenticatePacket(BasePacket):
    def _init(self):
        self.id = 1
        self.msg_type = 3
        self.version = NET_VERSION
        self.needs_ack = True

    def _str(self):
        return ', version: {}'.format(self.version)

    def _pack(self):
        self.data.purge()
        self.data.put_32(NET_VERSION)


class PreAuthapprovedPacket(BasePacket):
    def _init(self):
        self.msg_type = 4
        self.clientnum = None

    def _str(self):
        return ', got num {}'.format(self.clientnum)

    def _unpack(self):
        self.clientnum = self.data.get_32()


class AuthapprovedPacket(BasePacket):
    def _init(self):
        self.msg_type = 5
        self.clienttoken = self.playerid = self.num_chars = 0
        self.chars = []

    def __str__(self):
        string = 'Authapproved clientnum {} and playerid {}: {} chars ({})'
        return string.format(self.clienttoken, self.playerid, self.num_chars, self.chars)

    def _unpack(self):
        self.clienttoken = self.data.get_32()
        self.playerid = self.data.get_32()
        self.num_chars = self.data.get_8()
        for i in range(self.num_chars):
            name = self.data.get_string()
            Race = self.data.get_string()
            gender = self.data.get_string()
            traits = self.data.get_string()
            equipList = self.data.get_string()
            self.chars.append((name, Race, gender, traits, equipList))


class AuthrejectedPacket(BasePacket):
    def _init(self):
        self.msg_type = 6
        self.reason = ''

    def _str(self):
        return ' with reason >{}<.'.format(self.reason)

    def _unpack(self):
        self.reason = self.data.get_string()


class DisconnectPacket(BasePacket):
    def _init(self):
        self.msg_type = 7
        self.reason = ''

    def _str(self):
        return ' with reason >{}<'.format(self.reason)

    def _pack(self):
        self.data.purge()
        self.data.put_32(0)
        self.data.put_string('')

    def _unpack(self):
        self.data.get_32()  # crap
        self.reason = self.data.get_string()


class ChatPacket(BasePacket):
    SYSTEM = 0
    COMBAT = 1
    SAY = 2
    TELL = 3
    GROUP = 4
    GUILD = 5
    ALLIANCE = 6
    AUCTION = 7
    SHOUT = 8
    CHANNEL = 9
    TELLSELF = 10
    REPORT = 11
    ADVISOR = 12
    ADVICE = 13
    ADVICE_LIST = 14
    SERVER_TELL = 15
    GM = 16
    SERVER_INFO = 17
    NPC = 18
    NPCINTERNAL = 19
    SYSTEM_BASE = 20
    PET_ACTION = 21
    NPC_ME = 22
    NPC_MY = 23
    NPC_NARRATE = 24
    AWAY = 25
    END = 26

    def _init(self):
        self.msg_type = 8
        self.chat_type = 2
        self.recipient = ''
        self.text = ''
        self.translate = 0
        self.actor = 0
        self.channel_id = 0

    def _str(self):
        if self.SYSTEM == self.chat_type: chat_type = 'System'
        elif self.COMBAT == self.chat_type: chat_type = 'Combat'
        elif self.SAY == self.chat_type: chat_type = 'Say'
        elif self.TELL == self.chat_type: chat_type = 'Tell'
        elif self.GROUP == self.chat_type: chat_type = 'Group'
        elif self.GUILD == self.chat_type: chat_type = 'Guild'
        elif self.ALLIANCE == self.chat_type: chat_type = 'Alliance'
        elif self.AUCTION == self.chat_type: chat_type = 'Auction'
        elif self.SHOUT == self.chat_type: chat_type = 'Shout'
        elif self.CHANNEL == self.chat_type: chat_type = 'Channel'
        elif self.TELLSELF == self.chat_type: chat_type = 'Tellself'
        elif self.REPORT == self.chat_type: chat_type = 'Report'
        elif self.ADVISOR == self.chat_type: chat_type = 'Advisor'
        elif self.ADVICE == self.chat_type: chat_type = 'Advice'
        elif self.ADVICE_LIST == self.chat_type: chat_type = 'Advicelist'
        elif self.SERVER_TELL == self.chat_type: chat_type = 'Servertell'
        elif self.GM == self.chat_type: chat_type = 'GM'
        elif self.SERVER_INFO == self.chat_type: chat_type = 'Serverinfo'
        elif self.NPC == self.chat_type: chat_type = 'Npc'
        elif self.NPCINTERNAL == self.chat_type: chat_type = 'Npcinternal'
        elif self.SYSTEM_BASE == self.chat_type: chat_type = 'Systembase'
        elif self.PET_ACTION == self.chat_type: chat_type = 'Petaction'
        elif self.NPC_ME == self.chat_type: chat_type = 'Npcme'
        elif self.NPC_MY == self.chat_type: chat_type = 'Npcmy'
        elif self.NPC_NARRATE == self.chat_type: chat_type = 'Npcnarrate'
        elif self.AWAY == self.chat_type: chat_type = 'Away'
        elif self.END == self.chat_type: chat_type = 'End'
        recipient_str = self.recipient or 'me'
        translated = 'translated' if self.translate else 'untranslated'
        text = ': {0} by {1}: {2} ({3}, {4})'
        if self.chat_type == self.CHANNEL:
            text = ': In channel {5} by {1}: {2} ({3}, {4})'
        return text.format(chat_type, recipient_str, self.text,
            translated, self.actor, self.channel_id)

    def _pack(self):
        self.data.purge()
        self.data.put_8(self.chat_type)
        self.data.put_string(self.recipient)
        self.data.put_string(self.text)
        self.data.put_8(self.translate)
        self.data.put_32(self.actor)
        if self.chat_type == self.CHANNEL:
            self.data.put_16(self.channel_id)

    def _unpack(self):
        self.chat_type = self.data.get_8()
        self.recipient = self.data.get_string()
        self.text = self.data.get_string()
        self.translate = self.data.get_8()
        self.actor = self.data.get_32()
        if self.chat_type == self.CHANNEL:
            self.channel_id = self.data.get_16()


class ChannelJoinPacket(BasePacket):
    def _init(self):
        self.msg_type = 9
        self.name = ''

    def _str(self):
        return ': Joining channel {}'.format(self.name)

    def _pack(self):
        self.data.put_string(self.name)


class ChannelJoinedPacket(BasePacket):
    def _init(self):
        self.msg_type = 10
        self.name = ''
        self.channel_id = 0

    def _str(self):
        return ': Joined channel {} (id: {}).'.format(self.name, self.channel_id)

    def _unpack(self):
        self.name = self.data.get_string()
        self.channel_id = self.data.get_16()


class ChannelLeavePacket(BasePacket):
    def _init(self):
        self.msg_type = 11
        self.channel_id = 0

    def _str(self):
        return ': Leaving channel id {}'.format(self.channel_id)

    def _pack(self):
        self.data.put_16(self.channel_id)

class GuildCmdPacket(BasePacket):
    def _init(self):
        self.msg_type = 12

class UserCmdPacket(BasePacket):
    def _init(self):
        self.msg_type = 13
        self.command = ''

    def _str(self):
        return ': >{}<'.format(self.command)

    def _pack(self):
        self.data.purge()
        self.data.put_string(self.command)

    def _unpack(self):
        self.command = self.data.get_string()


class SystemPacket(BasePacket):
    def _init(self):
        self.msg_type = 14
        self.msg = ''

    def _str(self):
        return ': >{}<'.format(self.msg)

    def _unpack(self):
        self.data.get_32()  # crap
        self.msg = self.data.get_string()


class CharRejectPacket(BasePacket):
    def _init(self):
        self.msg_type = 15

class DeadReckoningPacket(BasePacket):
    def _init(self):
        self.msg_type = 16
        self.entity_id = 0
        self.counter = 0
        self.flags = 0
        self.mode = 0
        self.ang_vel = 0
        self.vel = (0, 0, 0)
        self.world_vel = (0, 0, 0)
        self.pos = (0, 0, 0)
        self.y_rot = 0
        self.sector = ''

    def _str(self):
        everything = (self.entity_id, self.counter, self.flags, self.mode, self.ang_vel,
                self.vel, self.world_vel, self.pos, self.y_rot, self.sector)
        return ': {}'.format(everything)

    def _unpack(self):
        self.entity_id = self.data.get_32()
        self.counter = self.data.get_8()

        self.flags = self.data.get_8()
        if self.flags & 1: self.mode = self.data.get_8()
        if self.flags & 2: self.ang_vel = self.data.get_f()

        if self.flags & 4: self.vel = (self.data.get_f(), 0, 0)
        if self.flags & 8: self.vel = (0, self.data.get_f(), 0)
        if self.flags & 16: self.vel = (0, 0, self.data.get_f())

        if self.flags & 32: self.world_vel = (self.data.get_f(), 0, 0)
        if self.flags & 64: self.world_vel = (0, self.data.get_f(), 0)
        if self.flags & 128: self.world_vel = (0, 0, self.data.get_f())

        self.pos = self.data.get_vector()
        self.y_rot = self.data.get_8()

        if self.data.get_32() == 4294967295: self.sector = self.data.get_string()
        else: self.sector = ''

    def _pack(self):
        self.data.put_32(self.entity_id)
        self.data.put_8(self.counter)

        self.data.put_8(self.flags)
        if self.flags & 1: self.data.put_8(self.mode)
        if self.flags & 2: self.data.put_f(self.ang_vel)

        if self.flags & 4: self.data.put_f(self.vel[0])
        if self.flags & 8: self.data.put_f(self.vel[1])
        if self.flags & 16: self.data.put_f(self.vel[2])

        if self.flags & 32: self.data.put_f(self.world_vel[0])
        if self.flags & 64: self.data.put_f(self.world_vel[1])
        if self.flags & 128: self.data.put_f(self.world_vel[2])

        self.data.put_vector(self.pos)
        self.data.put_8(self.y_rot)

        self.data.put_32(4294967295)
        self.data.put_string(self.sector)


class ForcePositionPacket(BasePacket):
    def _init(self):
        self.msg_type = 17

class CelPersistPacket(BasePacket):
    def _init(self):
        self.msg_type = 18

class ConfirmquestionPacket(BasePacket):
    def _init(self):
        self.msg_type = 19

class UserActionPacket(BasePacket):
    def _init(self):
        self.msg_type = 20

class AdminCmdPacket(BasePacket):
    def _init(self):
        self.msg_type = 21

class GuiInteractPacket(BasePacket):
    def _init(self):
        self.msg_type = 22

class GuiInventoryPacket(BasePacket):
    def _init(self):
        self.msg_type = 23
        self.command = 1
        self.itemcount = 0
        self.weight = 0
        self.version = 0
        self.money = ''
        self.items = list()
        self.total_emptied = 0
        self.emptied_items = list()

    def _str(self):
        if self.command == 1:
            string = ' Request Inv.'
        elif self.command == 2:
            string = ' Request update Inv.'
        else:
            string = ' items: {}, weight: {}, version: {}, money: {}'
            string = string.format(self.itemcount,
                self.weight, self.version, self.money)
            if self.command == 3:
                string += ' - updated: deleted {} items.'
                string = string.format(self.total_emptied)
            string += ' ' + str(self.items)
        return string

    def _pack(self):
        self.data.purge()
        self.data.put_8(self.command)  # request, should be 1

    def _unpack(self):
        self.command = self.data.get_8()
        if self.command in (0, 3):
            self.itemcount = self.data.get_32()
            if self.command == 3:
                self.total_emptied = self.data.get_32()
            else:
                self.total_emptied = 0
            self.weight = self.data.get_f()
            self.version = self.data.get_32()
            self.items = list()
            for i in range(self.itemcount):
                self.items.append({
                        'name': self.data.get_string(),
                        'mesh_name': self.data.get_32(),
                        'mat_name': self.data.get_32(),
                        'container': self.data.get_32(),
                        'slot': self.data.get_32(),
                        'stackcount': self.data.get_32(),
                        'weight': self.data.get_f(),
                        'size': self.data.get_f(),
                        'icon': self.data.get_string(),
                        'purify_status': self.data.get_8()})
            if self.command == 3:
                self.emptied_items = list()
                for i in range(self.total_emptied):
                    self.emptied_items.append({
                        'container': self.data.get_32(),
                        'slot': self.data.get_32()})
            self.money = [int(i) for i in self.data.get_string().split(',')]

class ViewItemPacket(BasePacket):
    def _init(self):
        self.msg_type = 24

class ViewContainerPacket(BasePacket):
    def _init(self):
        self.msg_type = 25

class ViewSketchPacket(BasePacket):
    def _init(self):
        self.msg_type = 26

class ViewActionLocationPacket(BasePacket):
    def _init(self):
        self.msg_type = 27

class ReadBookPacket(BasePacket):
    def _init(self):
        self.msg_type = 28
        self.title = ''
        self.text = ''

    def _str(self):
        return ': Got the book >{}<: {}..'.format(self.title, self.text[:40])

    def _unpack(self):
        self.title = self.data.get_string()
        self.text = self.data.get_string().replace('\r', '')


class WriteBookPacket(BasePacket):
    def _init(self):
        self.msg_type = 29

class UpdateItemPacket(BasePacket):
    def _init(self):
        self.msg_type = 30

class ModePacket(BasePacket):
    def _init(self):
        self.msg_type = 31

class WeatherPacket(BasePacket):
    def _init(self):
        self.msg_type = 32
        self.date = dict()
        self.sector = ''
        self.downfall = dict()
        self.fog = dict()

    def _str(self):
        if self.date:
            string = ': {}:{} - {}.{}.{}'.format(self.date['hour'],
                self.date['minute'], self.date['day'],
                self.date['month'], self.date['year'],)
        else:
            string = ': At sector {}:'.format(self.sector)
            if self.downfall:
                string += ' downfall with {} drops,'.format(self.downfall['drops'])
            else: string += ' no downfall,'

            if self.fog:
                string += ' fog with {} density'.format(self.fog['density'])
            else: string += ' no fog.'
        return string

    def _unpack(self):
        weather_type = self.data.get_8()
        if weather_type == 1:
            self.date = {
                         'minute': self.data.get_8(),
                         'hour': self.data.get_8(),
                         'day': self.data.get_8(),
                         'month': self.data.get_8(),
                         'year': self.data.get_32(),
                        }
        else:
            self.sector = self.data.get_string()
            if (weather_type & 8) or (weather_type & 4):  # some downfall
                self.downfall = {
                                 'drops': self.data.get_32(),
                                 'fade': self.data.get_32()
                                }
            if weather_type & 16:  # fog
                self.fog = {
                            'density': self.data.get_32(),
                            'fade': self.data.get_32(),
                            'rgb': (self.data.get_32(),
                                    self.data.get_32(),
                                    self.data.get_32()
                                   )
                           }


class NewsectorPacket(BasePacket):
    def _init(self):
        self.msg_type = 33

class GuiGuildPacket(BasePacket):
    def _init(self):
        self.msg_type = 34

class EquipmentPacket(BasePacket):
    def _init(self):
        self.msg_type = 35

class GuiExchangePacket(BasePacket):
    def _init(self):
        self.msg_type = 36

class ExchangeRequestPacket(BasePacket):
    def _init(self):
        self.msg_type = 37

class ExchangeAddItemPacket(BasePacket):
    def _init(self):
        self.msg_type = 38

class ExchangeRemoveItemPacket(BasePacket):
    def _init(self):
        self.msg_type = 39

class ExchangeAcceptPacket(BasePacket):
    def _init(self):
        self.msg_type = 40

class ExchangeStatusPacket(BasePacket):
    def _init(self):
        self.msg_type = 41

class ExchangeEndPacket(BasePacket):
    def _init(self):
        self.msg_type = 42

class ExchangeAutogivePacket(BasePacket):
    def _init(self):
        self.msg_type = 43

class ExchangeMoneyPacket(BasePacket):
    def _init(self):
        self.msg_type = 44

class GuiMerchantPacket(BasePacket):
    def _init(self):
        self.msg_type = 45

class GuiStoragePacket(BasePacket):
    def _init(self):
        self.msg_type = 46

class GroupCmdPacket(BasePacket):
    def _init(self):
        self.msg_type = 47

class GuiGroupPacket(BasePacket):
    def _init(self):
        self.msg_type = 48


class StatDRUpdatePacket(BasePacket):
    def _init(self):
        self.msg_type = 49
        self.entity_id = 0
        self.hp = self.hp_rate = 0
        self.mana = self.mana_rate = 0
        self.pstam = self.pstam_rate = 0
        self.mstam = self.mstam_rate = 0
        self.exp = self.prog = 0
        self.counter = 0

    def _str(self):
        string = ': {}-> hp: {} ({}), mana: {} ({}), pstam: {} ({}), '
        string += 'mstam: {} ({}), exp: {}, progr: {}, counter: {}'
        return string.format(self.entity_id, self.hp, self.hp_rate, self.mana,
                             self.mana_rate, self.pstam, self.pstam_rate,
                             self.mstam, self.mstam_rate, self.exp, self.prog,
                             self.counter)


    def _unpack(self):
        return # XXX
        self.entity_id = self.data.get_32()
        stats_flag = self.data.get_32()
        if stats_flag & 1: self.hp = self.data.get_f()
        if stats_flag & 4: self.hp_rate = self.data.get_f()
        if stats_flag & 8: self.mana = self.data.get_f()
        if stats_flag & 32: self.mana_rate = self.data.get_f()
        if stats_flag & 64: self.pstam = self.data.get_f()
        if stats_flag & 256: self.pstam_rate = self.data.get_f()
        if stats_flag & 512: self.mstam = self.data.get_f()
        if stats_flag & 2048: self.mstam_rate = self.data.get_f()
        if stats_flag & 4096: self.exp = self.data.get_32()
        if stats_flag & 8192: self.prog = self.data.get_32()
        self.counter = self.data.get_8()


class SpellBookPacket(BasePacket):
    def _init(self):
        self.msg_type = 50

class GlyphRequestPacket(BasePacket):
    def _init(self):
        self.msg_type = 51

class GlyphAssemblePacket(BasePacket):
    def _init(self):
        self.msg_type = 52

class PurifyGlyphPacket(BasePacket):
    def _init(self):
        self.msg_type = 53

class SpellCastPacket(BasePacket):
    def _init(self):
        self.msg_type = 54

class SpellCancelPacket(BasePacket):
    def _init(self):
        self.msg_type = 55

class EffectPacket(BasePacket):
    def _init(self):
        self.msg_type = 56

class EffectStopPacket(BasePacket):
    def _init(self):
        self.msg_type = 57

class NpcAuthEntPacket(BasePacket):
    def _init(self):
        self.msg_type = 58

class NpcListPacket(BasePacket):
    def _init(self):
        self.msg_type = 59

class GuitargetupdatePacket(BasePacket):
    def _init(self):
        self.msg_type = 60

class MapListPacket(BasePacket):
    def _init(self):
        self.msg_type = 61

class NpCommandListPacket(BasePacket):
    def _init(self):
        self.msg_type = 62

class NpcReadyPacket(BasePacket):
    def _init(self):
        self.msg_type = 63

class AllEntityPosPacket(BasePacket):
    def _init(self):
        self.msg_type = 64

class PersistAllEntitiesPacket(BasePacket):
    def _init(self):
        self.msg_type = 65

class NewNpcPacket(BasePacket):
    def _init(self):
        self.msg_type = 66

class PetitionPacket(BasePacket):
    def _init(self):
        self.msg_type = 67

class MsgstringsPacket(BasePacket):
    def _init(self):
        self.msg_type = 68

class CharacterDataPacket(BasePacket):
    def _init(self):
        self.msg_type = 69

class AuthCharacterPacket(BasePacket):
    def _init(self):
        self.id = 5
        self.msg_type = 70
        self.char_name = ''

    def _str(self):
        return ' ' + str(self.char_name)

    def _pack(self):
        self.data.purge()
        self.data.put_string(self.char_name)


class AuthCharacterApprovedPacket(BasePacket):
    def _init(self):
        self.msg_type = 71


class CharCreateCpPacket(BasePacket):
    def _init(self):
        self.msg_type = 72

class CombatEventPacket(BasePacket):
    def _init(self):
        self.msg_type = 73

class LootPacket(BasePacket):
    def _init(self):
        self.msg_type = 74

class LootitemPacket(BasePacket):
    def _init(self):
        self.msg_type = 75

class LootRemovePacket(BasePacket):
    def _init(self):
        self.msg_type = 76

class GuiSkillPacket(BasePacket):
    def _init(self):
        self.msg_type = 77

class OverrideActionPacket(BasePacket):
    def _init(self):
        self.msg_type = 78

class QuestListPacket(BasePacket):
    def _init(self):
        self.msg_type = 79

class QuestinfoPacket(BasePacket):
    def _init(self):
        self.msg_type = 80

class GmGuiPacket(BasePacket):
    def _init(self):
        self.msg_type = 81

class WorkCmdPacket(BasePacket):
    def _init(self):
        self.msg_type = 82

class BuddyListPacket(BasePacket):
    def _init(self):
        self.msg_type = 83
        self.online = list()
        self.offline = list()

    def _str(self):
        return ' {} buddies, {} online.'.format(
            len(self.online) + len(self.offline), len(self.online))

    def _unpack(self):
        self.online = list()
        self.offline = list()
        for i in range(self.data.get_32()):
            name = self.data.get_string()
            online = self.data.get_8()
            if online: self.online.append(name)
            else: self.offline.append(name)


class BuddyStatusPacket(BasePacket):
    def _init(self):
        self.msg_type = 84
        self.name = ''
        self.online = 0

    def _str(self):
        if self.online: status = 'online'
        else: status = 'offline'
        return ' {} -> {}.'.format(self.name, status)

    def _unpack(self):
        self.name = self.data.get_string()
        self.online = self.data.get_8()

class MotdPacket(BasePacket):
    def _init(self):
        self.msg_type = 85
        self.motd1 = self.motd2 = self.guild = self.guild_motd = ''

    def _str(self):
        string = ' >{0}..<, >{1}..<'
        if self.guild and self.guild_motd:
            string += ', MOTD of {2}: >{3}...<'
        return string.format(self.motd1[:10], self.motd2[:10],
                self.guild, self.guild_motd[:10])

    def _unpack(self):
        self.motd1 = self.data.get_string()
        self.motd2 = self.data.get_string()
        self.guild_motd = self.data.get_string()
        self.guild = self.data.get_string()


class MotdrequestPacket(BasePacket):
    def _init(self):
        self.msg_type = 86

    def _pack(self):
        self.data.purge()

class QuestionPacket(BasePacket):
    def _init(self):
        self.msg_type = 87

class QuestionResponsePacket(BasePacket):
    def _init(self):
        self.msg_type = 88

class SlotMovementPacket(BasePacket):
    def _init(self):
        self.msg_type = 89

        self.from_container = 0
        self.from_slot = 0
        self.to_container = 0
        self.to_slot = 0
        self.stack_count = 1
        self.pos_world = (0, 0, 0)
        self.rot_y = 0
        self.guarded = 1
        self.inplace = 1
        self.rot_x = 0
        self.rot_z = 0

    def _str(self):
        return ' ' +' '.join([str(x) for x in (
            self.from_container,
            self.from_slot,
            self.to_container,
            self.to_slot,
            self.stack_count,
            self.pos_world,
            self.rot_y,
            self.guarded,
            self.inplace,
            self.rot_x,
            self.rot_z)])

    def _unpack(self):
        self.from_container = self.data.get_32()
        self.from_slot = self.data.get_32()
        self.to_container = self.data.get_32()
        self.to_slot = self.data.get_32()
        self.stack_count = self.data.get_32()
        self.pos_world = self.data.get_vector()
        self.rot_y = self.data.get_f()
        self.guarded = self.data.get_8()
        self.inplace = self.data.get_8()
        self.rot_x = self.data.get_f()
        self.rot_z = self.data.get_f()

    def _pack(self):
        self.data.put_32(self.from_container)
        self.data.put_32(self.from_slot)
        self.data.put_32(self.to_container)
        self.data.put_32(self.to_slot)
        self.data.put_32(self.stack_count)
        self.data.put_vector(self.pos_world)
        self.data.put_f(self.rot_y)
        self.data.put_8(self.guarded)
        self.data.put_8(self.inplace)
        self.data.put_f(self.rot_x)
        self.data.put_f(self.rot_z)

class QuestionCancelPacket(BasePacket):
    def _init(self):
        self.msg_type = 90

class GuildmotdSetPacket(BasePacket):
    def _init(self):
        self.msg_type = 91

class PlaysoundPacket(BasePacket):
    def _init(self):
        self.msg_type = 92

class CharacterDetailsPacket(BasePacket):
    def _init(self):
        self.msg_type = 93

class CharDetailsRequestPacket(BasePacket):
    def _init(self):
        self.msg_type = 94

class CharDescUpdatePacket(BasePacket):
    def _init(self):
        self.msg_type = 95

class FactionInfoPacket(BasePacket):
    def _init(self):
        self.msg_type = 96

class QuestRewardPacket(BasePacket):
    def _init(self):
        self.msg_type = 97

class NameChangePacket(BasePacket):
    def _init(self):
        self.msg_type = 98
        self.entity_id = 0
        self.name = ''

    def _str(self):
        return ' of object {}: {}'.format(self.entity_id, self.name)

    def _unpack(self):
        self.entity_id = self.data.get_32()
        self.name = self.data.get_string()


class GuildChangePacket(BasePacket):
    def _init(self):
        self.msg_type = 99

class LockPickPacket(BasePacket):
    def _init(self):
        self.msg_type = 100

class GmSpawnItemsPacket(BasePacket):
    def _init(self):
        self.msg_type = 101

class GmSpawnTypesPacket(BasePacket):
    def _init(self):
        self.msg_type = 102

class GmSpawnItemPacket(BasePacket):
    def _init(self):
        self.msg_type = 103

class AdvicePacket(BasePacket):
    def _init(self):
        self.msg_type = 104

class ActiveMagicPacket(BasePacket):
    def _init(self):
        self.msg_type = 105

class GroupChangePacket(BasePacket):
    def _init(self):
        self.msg_type = 106

class MapActionPacket(BasePacket):
    def _init(self):
        self.msg_type = 107

class ClientStatusPacket(BasePacket):
    def _init(self):
        self.msg_type = 108
        self.ready = 1

    def _str(self):
        return ': Client ready'

    def _pack(self):
        self.data.purge()
        self.data.put_8(self.ready)

class TutorialPacket(BasePacket):
    def _init(self):
        self.msg_type = 109

class BankingPacket(BasePacket):
    def _init(self):
        self.msg_type = 110

class CmdDropPacket(BasePacket):
    def _init(self):
        self.msg_type = 111

class RequestMovementsPacket(BasePacket):
    def _init(self):
        self.msg_type = 112

    def _pack(self):
        self.data.purge()


class MoveinfoPacket(BasePacket):
    def _init(self):
        self.msg_type = 113
        self.modes = self.moves = 0
        self.modes_list = list()
        self.moves_list = list()

    def _str(self):
        return ': {} modes, {} moves.'.format(self.modes, self.moves)

    def _unpack(self):
        self.modes_list = list()
        self.moves_list = list()
        self.modes = self.data.get_32()
        self.moves = self.data.get_32()

        for i in range(self.modes):
            self.modes_list.append({
                'id': self.data.get_32(),
                'name': self.data.get_string(),
                'move_mod': self.data.get_vector(),
                'rotate_mod': self.data.get_vector(),
                'idle_anim': self.data.get_string()})

        for i in range(self.moves):
            self.moves_list.append({
                'id': self.data.get_32(),
                'name': self.data.get_string(),
                'base_move': self.data.get_vector(),
                'base_rotate': self.data.get_vector()})


class MovemodPacket(BasePacket):
    def _init(self):
        self.msg_type = 114

class MovelockPacket(BasePacket):
    def _init(self):
        self.msg_type = 115

class CharDeletePacket(BasePacket):
    def _init(self):
        self.msg_type = 116

class CharCreateParentsPacket(BasePacket):
    def _init(self):
        self.msg_type = 117

class CharCreateChildhoodPacket(BasePacket):
    def _init(self):
        self.msg_type = 118

class CharCreateLifeEventsPacket(BasePacket):
    def _init(self):
        self.msg_type = 119

class CharCreateUploadPacket(BasePacket):
    def _init(self):
        self.msg_type = 120

class CharCreateVerifyPacket(BasePacket):
    def _init(self):
        self.msg_type = 121

class CharCreateNamePacket(BasePacket):
    def _init(self):
        self.msg_type = 122

class PersistWorldRequestPacket(BasePacket):
    def _init(self):
        self.msg_type = 123

    def _pack(self):
        self.data.purge()


class PersistWorldPacket(BasePacket):
    def _init(self):
        self.msg_type = 124
        self.pos = (0, 0, 0)
        self.sector = ''

    def _str(self):
        return ': {} - {}'.format(self.sector, self.pos)

    def _unpack(self):
        self.pos = self.data.get_vector()
        self.sector = self.data.get_string()


class PersistActorRequestPacket(BasePacket):
    def _init(self):
        self.msg_type = 125

    def _str(self):
        return ''

    def _pack(self): pass


class PersistActorPacket(BasePacket):
    def _init(self):
        self.msg_type = 126

        self.entity_id = 0
        self.counter = 0
        self.mode = 0
        self.ang_vel = 0
        self.vel = (0, 0, 0)
        self.world_vel = (0, 0, 0)
        self.pos = (0, 0, 0)
        self.y_rot = 0
        self.sector = ''

        self.type = 0
        self.masquerade_type = 0
        self.control = 0
        self.name = ''
        self.guild = ''

        self.factname = 0
        self.matname = 0
        self.race = 0
        self.mount_factname = 0
        self.mounter_anim = 0

        self.gender = 0
        self.helm_group = ''
        self.bracer_group = ''
        self.belt_group = ''
        self.cloak_group = ''

        self.top = (0, 0, 0)
        self.bottom = (0, 0, 0)
        self.offset_2 = (0, 0, 0)

        self.tex_parts = ''
        self.equipment = ''

        self.server_mode = 0
        self.player_id = 0
        self.group_id = 0
        self.owner_id = 0
        self.instance = 0

        self.scale = 0
        self.mount_scale = 0
        self.flags = 0

    def _str(self):
        everything = (self.entity_id, self.counter, self.pos, self.type,
            self.masquerade_type, self.control, self.name, self.guild,
            self.factname, self.matname, self.race, self.mount_factname,
            self.mounter_anim, self.gender, self.helm_group,
            self.bracer_group, self.belt_group, self.cloak_group, self.top,
            self.bottom, self.offset_2, self.tex_parts, self.equipment,
            self.server_mode, self.player_id, self.group_id, self.owner_id,
            self.instance, self.scale, self.mount_scale, self.flags)
        return ': {}'.format(everything)

    def _unpack(self):
        self.entity_id = self.data.get_32()
        self.counter = self.data.get_8()

        self.flags = self.data.get_8()
        if self.flags & 1: self.mode = self.data.get_8()
        if self.flags & 2: self.ang_vel = self.data.get_f()

        if self.flags & 4: self.vel = (self.data.get_f(), 0, 0)
        if self.flags & 8: self.vel = (0, self.data.get_f(), 0)
        if self.flags & 16: self.vel = (0, 0, self.data.get_f())

        if self.flags & 32: self.world_vel = (self.data.get_f(), 0, 0)
        if self.flags & 64: self.world_vel = (0, self.data.get_f(), 0)
        if self.flags & 128: self.world_vel = (0, 0, self.data.get_f())

        self.pos = self.data.get_vector()
        self.y_rot = self.data.get_8()

        if self.data.get_32() == 4294967295: self.sector = self.data.get_string()
        else: self.sector = ''

        self.type = self.data.get_32()
        self.masquerade_type = self.data.get_32()
        self.control = self.data.get_8()
        self.name = self.data.get_string()
        self.guild = self.data.get_string()

        self.factname = self.data.get_32()
        self.matname = self.data.get_32()
        self.race = self.data.get_32()
        self.mount_factname = self.data.get_32()
        self.mounter_anim = self.data.get_32()

        self.gender = self.data.get_16()
        self.helm_group = self.data.get_string()
        self.bracer_group = self.data.get_string()
        self.belt_group = self.data.get_string()
        self.cloak_group = self.data.get_string()

        self.top = self.data.get_vector()
        self.bottom = self.data.get_vector()
        self.offset_2 = self.data.get_vector()

        self.tex_parts = self.data.get_string()
        self.equipment = self.data.get_string()

        self.server_mode = self.data.get_8()
        self.player_id = self.data.get_32()
        self.group_id = self.data.get_32()
        self.owner_id = self.data.get_32()
        self.instance = self.data.get_32()

        self.scale = self.data.get_f()
        self.mount_scale = self.data.get_f()

        self.flags = self.data.get_32()


class PersistItemPacket(BasePacket):
    def _init(self):
        self.msg_type = 127

        self.eid = 0
        self.type = 0
        self.name = ''
        self.facname = 0
        self.matname = 0
        self.sector = 0
        self.pos  = (0, 0, 0)
        self.rot_x = 0
        self.rot_y = 0
        self.rot_z = 0
        # 1: collide, 2: nopickup
        self.flags = 0

    def _str(self):
        return ' ' + ' '.join([str(x) for x in (
        self.eid,
        self.type,
        self.name,
        self.facname,
        self.matname,
        self.sector,
        self.pos ,
        self.rot_x,
        self.rot_y,
        self.rot_z,
        self.flags
        )])

    def _unpack(self):
        self.eid = self.data.get_32()
        self.type = self.data.get_32()
        self.name = self.data.get_string()
        self.facname = self.data.get_32()
        self.matname = self.data.get_32()
        self.sector = self.data.get_32()
        self.pos  = self.data.get_vector()
        self.rot_x = self.data.get_f()
        self.rot_y = self.data.get_f()
        self.rot_z = self.data.get_f()
        if self.data.data:
            self.flags = self.data.get_32()

class PersistActionLocationPacket(BasePacket):
    def _init(self):
        self.msg_type = 128

        self.obj_eid = 0
        self.obj_type = 0
        self.obj_name = ''
        self.obj_sector = ''
        self.obj_mesh = ''

    def _str(self):
        return ': {} at sector {}: {}'.format(
            self.obj_type, self.obj_sector, self.obj_name)

    def _unpack(self):
        self.obj_eid = self.data.get_32()
        self.obj_type = self.data.get_32()
        self.obj_name = self.data.get_string()
        self.obj_sector = self.data.get_string()
        self.obj_mesh = self.data.get_string()


class PersistAllPacket(BasePacket):
    def _init(self):
        self.msg_type = 129

class RemoveObjectPacket(BasePacket):
    def _init(self):
        self.msg_type = 130
        self.entity_id = 0

    def _str(self):
        return ', remove object {}'.format(self.entity_id)

    def _unpack(self):
        self.entity_id = self.data.get_32()


class ChangeTraitPacket(BasePacket):
    def _init(self):
        self.msg_type = 131

class DamageEventPacket(BasePacket):
    def _init(self):
        self.msg_type = 132

class DeathEventPacket(BasePacket):
    def _init(self):
        self.msg_type = 133

class TargetEventPacket(BasePacket):
    def _init(self):
        self.msg_type = 134

class ZPointEventPacket(BasePacket):
    def _init(self):
        self.msg_type = 135

class BuyEventPacket(BasePacket):
    def _init(self):
        self.msg_type = 136

class SellEventPacket(BasePacket):
    def _init(self):
        self.msg_type = 137

class PickupEventPacket(BasePacket):
    def _init(self):
        self.msg_type = 138

class DropEventPacket(BasePacket):
    def _init(self):
        self.msg_type = 139

class LootEventPacket(BasePacket):
    def _init(self):
        self.msg_type = 140

class ConnectEventPacket(BasePacket):
    def _init(self):
        self.msg_type = 141

class MovementEventPacket(BasePacket):
    def _init(self):
        self.msg_type = 142

class GenericEventPacket(BasePacket):
    def _init(self):
        self.msg_type = 143

class SoundEventPacket(BasePacket):
    def _init(self):
        self.msg_type = 144

class CharCreateTraitsPacket(BasePacket):
    def _init(self):
        self.msg_type = 145

class StatsPacket(BasePacket):
    def _init(self):
        self.msg_type = 146

class PetCommandPacket(BasePacket):
    def _init(self):
        self.msg_type = 147

class PetSkillPacket(BasePacket):
    def _init(self):
        self.msg_type = 148

class CraftInfoPacket(BasePacket):
    def _init(self):
        self.msg_type = 149
        self.text = ''

    def _str(self): return ' ' + self.text
    def _unpack(self): self.text = self.data.get_string()

class PetitionRequestPacket(BasePacket):
    def _init(self):
        self.msg_type = 150

class HeartbeatPacket(BasePacket):
    def _init(self):
        self.msg_type = 151
        self.needs_ack = True

    def _str(self): return ''
    def _pack(self): self.data.purge()


class NpcCommandPacket(BasePacket):
    def _init(self):
        self.msg_type = 152

class MinigameStartStopPacket(BasePacket):
    def _init(self):
        self.msg_type = 153

class MinigameBoardPacket(BasePacket):
    def _init(self):
        self.msg_type = 154

class MinigameUpdatePacket(BasePacket):
    def _init(self):
        self.msg_type = 155

class EntrancePacket(BasePacket):
    def _init(self):
        self.msg_type = 156

class GmEventListPacket(BasePacket):
    def _init(self):
        self.msg_type = 157

class GmEventInfoPacket(BasePacket):
    def _init(self):
        self.msg_type = 158

class SequencePacket(BasePacket):
    def _init(self):
        self.msg_type = 159

class NpcRaceListPacket(BasePacket):
    def _init(self):
        self.msg_type = 160

class IntroductionPacket(BasePacket):
    def _init(self):
        self.msg_type = 161

class CachefilePacket(BasePacket):
    def _init(self):
        self.msg_type = 162

class DialogMenuPacket(BasePacket):
    def _init(self):
        self.msg_type = 163

class SimpleStringPacket(BasePacket):
    def _init(self):
        self.msg_type = 164

class OrderEdTestPacket(BasePacket):
    def _init(self):
        self.msg_type = 165

class GenericCmdPacket(BasePacket):
    def _init(self):
        self.msg_type = 166

class CraftCancelPacket(BasePacket):
    def _init(self):
        self.msg_type = 167

class MusicalSheetPacket(BasePacket):
    def _init(self):
        self.msg_type = 168

class PlaySongPacket(BasePacket):
    def _init(self):
        self.msg_type = 169

class StopSongPacket(BasePacket):
    def _init(self):
        self.msg_type = 170


message_type = [
    AckPacket,                      # 0
    PingPacket,                     # 1
    AuthenticatePacket,             # 2
    PreauthenticatePacket,          # 3
    PreAuthapprovedPacket,          # 4
    AuthapprovedPacket,             # 5
    AuthrejectedPacket,             # 6 not used
    DisconnectPacket,               # 7
    ChatPacket,                     # 8
    ChannelJoinPacket,              # 9
    ChannelJoinedPacket,            # 10
    ChannelLeavePacket,             # 11
    GuildCmdPacket,                 # 12
    UserCmdPacket,                  # 13
    SystemPacket,                   # 14
    CharRejectPacket,               # 15
    DeadReckoningPacket,            # 16
    ForcePositionPacket,            # 17
    CelPersistPacket,               # 18
    ConfirmquestionPacket,          # 19
    UserActionPacket,               # 20
    AdminCmdPacket,                 # 21
    GuiInteractPacket,              # 22
    GuiInventoryPacket,             # 23
    ViewItemPacket,                 # 24
    ViewContainerPacket,            # 25
    ViewSketchPacket,               # 26
    ViewActionLocationPacket,       # 27
    ReadBookPacket,                 # 28
    WriteBookPacket,                # 29
    UpdateItemPacket,               # 30
    ModePacket,                     # 31
    WeatherPacket,                  # 32 partly
    NewsectorPacket,                # 33
    GuiGuildPacket,                 # 34
    EquipmentPacket,                # 35
    GuiExchangePacket,              # 36
    ExchangeRequestPacket,          # 37
    ExchangeAddItemPacket,          # 38
    ExchangeRemoveItemPacket,       # 39
    ExchangeAcceptPacket,           # 40
    ExchangeStatusPacket,           # 41
    ExchangeEndPacket,              # 42
    ExchangeAutogivePacket,         # 43
    ExchangeMoneyPacket,            # 44
    GuiMerchantPacket,              # 45
    GuiStoragePacket,               # 46
    GroupCmdPacket,                 # 47
    GuiGroupPacket,                 # 48
    StatDRUpdatePacket,             # 49
    SpellBookPacket,                # 50
    GlyphRequestPacket,             # 51
    GlyphAssemblePacket,            # 52
    PurifyGlyphPacket,              # 53
    SpellCastPacket,                # 54
    SpellCancelPacket,              # 55
    EffectPacket,                   # 56
    EffectStopPacket,               # 57
    NpcAuthEntPacket,               # 58
    NpcListPacket,                  # 59
    GuitargetupdatePacket,          # 60
    MapListPacket,                  # 61
    NpCommandListPacket,            # 62
    NpcReadyPacket,                 # 63
    AllEntityPosPacket,             # 64
    PersistAllEntitiesPacket,       # 65
    NewNpcPacket,                   # 66
    PetitionPacket,                 # 67
    MsgstringsPacket,               # 68
    CharacterDataPacket,            # 69
    AuthCharacterPacket,            # 70
    AuthCharacterApprovedPacket,    # 71
    CharCreateCpPacket,             # 72
    CombatEventPacket,              # 73
    LootPacket,                     # 74
    LootitemPacket,                 # 75
    LootRemovePacket,               # 76
    GuiSkillPacket,                 # 77
    OverrideActionPacket,           # 78
    QuestListPacket,                # 79
    QuestinfoPacket,                # 80
    GmGuiPacket,                    # 81
    WorkCmdPacket,                  # 82
    BuddyListPacket,                # 83
    BuddyStatusPacket,              # 84
    MotdPacket,                     # 85
    MotdrequestPacket,              # 86
    QuestionPacket,                 # 87
    QuestionResponsePacket,         # 88
    SlotMovementPacket,             # 89
    QuestionCancelPacket,           # 90
    GuildmotdSetPacket,             # 91
    PlaysoundPacket,                # 92
    CharacterDetailsPacket,         # 93
    CharDetailsRequestPacket,       # 94
    CharDescUpdatePacket,           # 95
    FactionInfoPacket,              # 96
    QuestRewardPacket,              # 97
    NameChangePacket,               # 98
    GuildChangePacket,              # 99
    LockPickPacket,                 # 100
    GmSpawnItemsPacket,             # 101
    GmSpawnTypesPacket,             # 102
    GmSpawnItemPacket,              # 103
    AdvicePacket,                   # 104
    ActiveMagicPacket,              # 105
    GroupChangePacket,              # 106
    MapActionPacket,                # 107
    ClientStatusPacket,             # 108
    TutorialPacket,                 # 109
    BankingPacket,                  # 110
    CmdDropPacket,                  # 111
    RequestMovementsPacket,         # 112
    MoveinfoPacket,                 # 113
    MovemodPacket,                  # 114
    MovelockPacket,                 # 115
    CharDeletePacket,               # 116
    CharCreateParentsPacket,        # 117
    CharCreateChildhoodPacket,      # 118
    CharCreateLifeEventsPacket,     # 119
    CharCreateUploadPacket,         # 120
    CharCreateVerifyPacket,         # 121
    CharCreateNamePacket,           # 122
    PersistWorldRequestPacket,      # 123
    PersistWorldPacket,             # 124
    PersistActorRequestPacket,      # 125
    PersistActorPacket,             # 126 partly
    PersistItemPacket,              # 127
    PersistActionLocationPacket,    # 128
    PersistAllPacket,               # 129
    RemoveObjectPacket,             # 130
    ChangeTraitPacket,              # 131
    DamageEventPacket,              # 132
    DeathEventPacket,               # 133
    TargetEventPacket,              # 134
    ZPointEventPacket,              # 135
    BuyEventPacket,                 # 136
    SellEventPacket,                # 137
    PickupEventPacket,              # 138
    DropEventPacket,                # 139
    LootEventPacket,                # 140
    ConnectEventPacket,             # 141
    MovementEventPacket,            # 142
    GenericEventPacket,             # 143
    SoundEventPacket,               # 144
    CharCreateTraitsPacket,         # 145
    StatsPacket,                    # 146
    PetCommandPacket,               # 147
    PetSkillPacket,                 # 148
    CraftInfoPacket,                # 149
    PetitionRequestPacket,          # 150
    HeartbeatPacket,                # 151
    NpcCommandPacket,               # 152
    MinigameStartStopPacket,        # 153
    MinigameBoardPacket,            # 154
    MinigameUpdatePacket,           # 155
    EntrancePacket,                 # 156
    GmEventListPacket,              # 157
    GmEventInfoPacket,              # 158
    SequencePacket,                 # 159
    NpcRaceListPacket,              # 160
    IntroductionPacket,             # 161
    CachefilePacket,                # 162
    DialogMenuPacket,               # 163
    SimpleStringPacket,             # 164
    OrderEdTestPacket,              # 165
    GenericCmdPacket,               # 166
    CraftCancelPacket,              # 167
    MusicalSheetPacket,             # 168
    PlaySongPacket,                 # 169
    StopSongPacket,                 # 170
]
