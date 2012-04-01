import logging
import hashlib

from strohman.interface import proto


LOGGER = logging.getLogger(__name__)


class Interface(proto.Interface):
    def __init__(self, ip, port, username, password):
        super().__init__(ip, port)
        self.logger = LOGGER.getChild(self.__class__.__name__)
        self.username = username
        self.password = hashlib.md5(password.encode('utf-8')).hexdigest()
        self.do_start()

    def do_start(self):
        super().do_start()
        self.do_ping()

    ## net events
    def on_ping(self, handler, is_up, delay):
        self.logger.info(str(handler))
        if not is_up: self.sched.enter(2, 1, handler.ping, tuple())
        else:
            super().on_ping(handler, is_up, delay)
            self.do_auth(self.username, self.password)

    def on_connection_error(self):
        self.logger.error('Connection error, restarting')
        self.close()
        self.sched.enter(2, 1, self.do_start, tuple())

    def on_auth_done(self, handler, chars):
        super().on_auth_done(handler, chars)
        char = chars[0][0]
        self.logger.info('Login with {}.'.format(char))
        self.do_login(char)

    def on_auth_failed(self, handler):
        super().on_auth_failed(handler)
        self.do_disconnect()

    def on_login(self, handler):
        super().on_login(handler)
        self.logger.info('Logged in.')
        self.do_setup_env()

    def on_chat_tell(self, handler, recipient, text):
        self.do_chat_tell(recipient, 'Sorry, I am away!')
