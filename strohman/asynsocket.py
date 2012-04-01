import time
import sched
import asyncore
dispatcher = asyncore.dispatcher


class asynchat(asyncore.dispatcher):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._in_buffer = ''
        self._out_buffer = ''
        self.terminator = '\n'

    def handle_read(self):
        data = self.recv(4096)
        try: self._in_buffer += data.decode('utf-8')
        except UnicodeDecodeError: raise Exception(repr(data))
        while self.terminator in self._in_buffer:
            (msg, self._in_buffer) = self._in_buffer.split(self.terminator, 1)
            self.found_terminator(msg)

    def handle_write(self):
        num_send = self.send(self._out_buffer.encode('utf-8'))
        self._out_buffer = self._out_buffer[num_send:]

    def writable(self):
        return bool(self._out_buffer)

    def send_line(self, message):
        self._out_buffer += message + self.terminator

    def found_terminator(self, message):
        '''Implement'''
        pass


class asynschedcore(sched.scheduler):
# taken from http://stackoverflow.com/users/466143/helmut
# http://stackoverflow.com/questions/1036646/pythons-asyncore-to-periodically-send-data-using-a-variable-timeout-is-there-a/4956882#4956882
    """Combine sched.scheduler and asyncore.loop."""
    # On receiving a signal asyncore kindly restarts select. However the signal
    # handler might change the scheduler instance. This tunable determines the
    # maximum time in seconds to spend in asycore.loop before reexamining the
    # scheduler.
    maxloop = 30

    def __init__(self, map=None):
        sched.scheduler.__init__(self, time.time, self._delay)
        if map is None:
            self._asynmap = asyncore.socket_map
        else:
            self._asynmap = map
        self._abort_delay = False

    def _maybe_abort_delay(self):
        if not self._abort_delay:
            return False
        # Returning from this function causes the next event to be executed, so
        # it might be executed too early. This can be avoided by modifying the
        # head of the queue. Also note that enterabs sets _abort_delay to True.
        self.enterabs(0, 0, lambda: None, ())
        self._abort_delay = False
        return True

    def _delay(self, timeout):
        if self._maybe_abort_delay():
            return
        if 0 == timeout:
            # Should we support this hack, too?
            # asyncore.loop(0, map=self._asynmap, count=1)
            return
        now = time.time()
        finish = now + timeout
        while now < finish and self._asynmap:
            asyncore.loop(min(finish - now, self.maxloop), map=self._asynmap,
                          count=1)
            if self._maybe_abort_delay():
                return
            now = time.time()
        if now < finish:
            time.sleep(finish - now)

    def enterabs(self, abstime, priority, action, argument):
        # We might insert an event before the currently next event.
        self._abort_delay = True
        return sched.scheduler.enterabs(self, abstime, priority, action,
                                        argument)

    # Overwriting enter is not necessary,
    # because it is implemented using enter.

    def cancel(self, event):
        # We might cancel the next event.
        self._abort_delay = True
        return sched.scheduler.cancel(self, event)

    def run(self):
        """Runs as long as either an event is scheduled or there are
        sockets in the map."""
        while True:
            if not self.empty():
                sched.scheduler.run(self)
            elif self._asynmap:
                asyncore.loop(self.maxloop, map=self._asynmap, count=1)
            else: break
