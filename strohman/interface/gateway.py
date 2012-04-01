import logging

from strohman.interface import auto


LOGGER = logging.getLogger(__name__)


class Interface(auto.Interface):
    def __init__(self, gateway, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.logger = LOGGER.getChild(self.__class__.__name__)
        self.gateway = gateway
        self.is_ready = False

    def gw_chat_tell(self, by, to, text):
        self.do_chat_tell(to, 'From {}: {}'.format(by, text))

#    def gw_command(self, by, cmd):
#        if mc_string == 'date':
#            date_string = '{hour}:{minute} - {day}.{month}.{year}'
#            date_string = date_string.format(**self.weather_handler.last_date)
#            self.gateway.irc.gw_chat_tell(
#            self.send_message(m_id, 'system', 'msg', date_string)
#        elif mc_string.startswith('who'):
#            self.do_user_cmd('/' + mc_string)

    def on_login(self, handler):
        super().on_login(handler)
        self.is_ready = True

    def on_disconnect(self, handler):
        super().on_disconnect(handler)
        self.is_ready = False

    def on_system_msg(self, handler, text):
        self.gateway.irc.gw_system(text)

    def on_chat_server_info(self, handler, sender, text):
        self.gateway.irc.gw_system('From {}: {}'.format(sender, text))

    def on_chat_system_base(self, handler, sender, text):
        self.gateway.irc.gw_system('From {}: {}'.format(sender, text))

    def on_chat_tell(self, handler, sender, text):
        self.gateway.irc.gw_chat_tell(sender, text)

    def on_chat_say(self, handler, sender, text):
        self.gateway.irc.gw_chat_say(sender, text)

    def on_chat_shout(self, handler, sender, text):
        self.gateway.irc.gw_chat_say(sender, text)
