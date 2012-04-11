Strohman
========

Usage
-----

1. Get it.
2. Copy 'strohman/config.py.example' to 'strohman/config.py' and change it.
3. Run 'bin/strohman' with python 3.x.


Issues
------

1. strohman/net/netpacket.py (line 816):
   StatDRUpdatePacket: fix unknown error in unpacking

2. strohman/net/handlers.py (line 230):
   Chat: handle KeyError if user tries to send chat to unknown channel

3. strohman/net/connection.py (line 135):
   Asynsocket: handle errno.EINVAL - send error (resend packet?)

4. strohman/net/connection.py (line 142):
   Asynsocket: If the client restarts, but the server keeps sending heartbeats,
               neither the server nor the client (no timeout) disconnect.
