from strohman.net import connection
from strohman.net import netpacket
from strohman.net import handlers
from strohman import asynsocket


class Interface:
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port
        self.sched = asynsocket.asynschedcore()
        self.connection = None
        self.weather_handler = self.vitals_handler = None
        self.chat_handler = self.actor_handler = self.comand_handler = None

    def close(self):
        if not self.connection is None and self.connection.connected:
            self.do_disconnect()
            self.run()

    def run(self):
       self.sched.run()

    ## net events
    def on_ping(self, handler, is_up, delay): handler.close()
    def on_connection_error(self): pass
    def on_disconnect(self, handler): self.connection.close()
    def on_auth_done(self, handler, chars): handler.close()
    def on_auth_failed(self, handler): handler.close()
    def on_login(self, handler): handler.close()

    ## chat events
    def on_system_msg(self, handler, msg): pass
    def on_chat_joined(self, handler, channel_name): pass
    def on_chat_system(self, handler, recipient, text): pass
    def on_chat_combat(self, handler, recipient, text): pass
    def on_chat_say(self, handler, recipient, text): pass
    def on_chat_tell(self, handler, recipient, text): pass
    def on_chat_group(self, handler, recipient, text): pass
    def on_chat_guild(self, handler, recipient, text): pass
    def on_chat_alliance(self, handler, recipient, text): pass
    def on_chat_auction(self, handler, recipient, text): pass
    def on_chat_shout(self, handler, recipient, text): pass
    def on_chat_channel(self, handler, recipient, text, channel): pass
    def on_chat_tellself(self, handler, recipient, text): pass
    def on_chat_report(self, handler, recipient, text): pass
    def on_chat_advisor(self, handler, recipient, text): pass
    def on_chat_advice(self, handler, recipient, text): pass
    def on_chat_advice_list(self, handler, recipient, text): pass
    def on_chat_server_tell(self, handler, recipient, text): pass
    def on_chat_gm(self, handler, recipient, text): pass
    def on_chat_server_info(self, handler, recipient, text): pass
    def on_chat_npc(self, handler, recipient, text): pass
    def on_chat_system_base(self, handler, recipient, text): pass
    def on_chat_pet_action(self, handler, recipient, text): pass
    def on_chat_npc_me(self, handler, recipient, text): pass
    def on_chat_npc_my(self, handler, recipient, text): pass
    def on_chat_npc_narrate(self, handler, recipient, text): pass
    def on_chat_away(self, handler, recipient, text): pass
    def on_chat_end(self, handler, recipient, text): pass

    ## actor events
    def on_actor_new(self, handler, entity_id): pass
    def on_actor_del(self, handler, entity_id): pass
    def on_actor_moved(self, handler, entity_id): pass

    ## weather events
    def on_weather_timeup(self, hander, last_date): pass
    def on_weather_weatherup(self, hander, sector, wether): pass

######################

    def do_start(self):
        self.connection = connection.Connection(self, self.ip, self.port)

    ## net handlers
    def do_ping(self):
        handlers.Ping(self)

    def do_disconnect(self):
        handlers.Disconnect(self)

    def do_auth(self, username, password):
        self.vitals_handler = handlers.Vitals(self)
        handlers.Authenticate(self, username, password)

    def do_login(self, char_name):
        handlers.Login(self, char_name)

    def do_setup_env(self):
        self.weather_handler = handlers.Weather(self)
        self.chat_handler = handlers.Chat(self)
        self.command_handler = handlers.Command(self)
        self.actor_handler = handlers.Actors(self)

    ## command handlers
    def do_user_cmd(self, cmd):
        self.command_handler.user_cmd(cmd)

    ## chat handlers
    def do_chat_channel_join(self, channel_name):
        self.chat_handler.join_channel(channel_name)
    def do_chat_channel_leave(self, channel_name):
        self.chat_handler.leave_channel(channel_name)
    def do_chat_say(self, recipient, text):
        self.chat_handler.send_chat(netpacket.ChatPacket.SAY, recipient, text)
    def do_chat_tell(self, recipient, text):
        self.chat_handler.send_chat(netpacket.ChatPacket.TELL, recipient, text)
    def do_chat_group(self, recipient, text):
        self.chat_handler.send_chat(netpacket.ChatPacket.GROUP, recipient, text)
    def do_chat_guild(self, recipient, text):
        self.chat_handler.send_chat(netpacket.ChatPacket.GUILD, recipient, text)
    def do_chat_alliance(self, recipient, text):
        self.chat_handler.send_chat(netpacket.ChatPacket.ALLIANCE, recipient, text)
    def do_chat_auction(self, recipient, text):
        self.chat_handler.send_chat(netpacket.ChatPacket.AUCTION, recipient, text)
    def do_chat_shout(self, recipient, text):
        self.chat_handler.send_chat(netpacket.ChatPacket.SHOUT, recipient, text)
    def do_chat_channel(self, channel, text):
        self.chat_handler.send_chat(netpacket.ChatPacket.CHANNEL, channel, text)
    def do_chat_report(self, recipient, text):
        self.chat_handler.send_chat(netpacket.ChatPacket.REPORT, recipient, text)
    def do_chat_advisor(self, recipient, text):
        self.chat_handler.send_chat(netpacket.ChatPacket.ADVISOR, recipient, text)
    def do_chat_advice(self, recipient, text):
        self.chat_handler.send_chat(netpacket.ChatPacket.ADVICE, recipient, text)
    def do_chat_npc(self, recipient, text):
        self.chat_handler.send_chat(netpacket.ChatPacket.NPC, recipient, text)
