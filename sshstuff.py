"""do some useful things over SSH"""

from io import BytesIO
from paramiko.client import (SSHClient,
                             AutoAddPolicy,
                             RejectPolicy,
                             WarningPolicy)

import socket  # mainly for socket errors
from select import select
from threading import Event, Thread

import log
l = log.getLogger(__name__)

BUF_SIZE = 512


def _feed_file(source, destination, event, close=False):
    """a thread feeding a source file-like object to a destination file-like"""
    # this will block when waiting to read or write
    l.debug("feeder thread started")
    while True:
        l.debug("feeder reading from input")
        buf = source.read(BUF_SIZE)
        l.debug("feeder read %s bytes", len(buf))
        l.debug(repr(buf))
        if len(buf) == 0:  # EOF
            break
        destination.write(buf)
        l.debug("feeder wrote %s bytes", len(buf))
    l.debug("feeder done")
    if close:
        l.debug("feeder closing destination")
        destination.close()
    source.close()
    event.set()


def _chan_sender(source, chan, event):
    """send everything in the buffer to the channel, then shut sending down"""
    while True:
        l.debug("reading from input")
        buf = source.read(BUF_SIZE)
        if len(buf) == 0:
            break
        l.debug("sending to channel")
        chan.sendall(buf)

    l.debug("shutting channel write side")
    chan.shutdown_write()
    source.close()
    event.set()


def _chan_receiver(chan_recv, dest, event):
    """receive what we can from a channel until EOF"""
    while True:
        l.debug("reading from channel")
        buf = chan_recv(BUF_SIZE)
        if len(buf) == 0:
            break
        l.debug("writing to output")
        dest.write(buf)

    l.debug("EOF encountered, closing destination")
    event.set()


class DBSSHClient(SSHClient):
    """
    an SSH client, but with emulated file transfer to get over DropBear
    limitations
    """
    def pipe_through_filter2(self, command, i_buf):
        """
        pipe input through a UNIX pipe on the remote end,
        returning the result
        """
        # execute the command
        transport = self.get_transport()
        chan = transport.open_session()
        chan.exec_command(command)

    def pipe_through_filter3(self, command, i_buf):
        """
        pipe input through a UNIX pipe on the remote end,
        returning the result
        """
        # prepare for continuous feeding
        o_buf = BytesIO()
        e_buf = BytesIO()

        # run the command
        i, o, e = self.exec_command(command)
        i_c, o_c, e_c = i.channel, o.channel, e.channel

        # wait for them to finish
        while not o.channel.exit_status_ready():
            l.debug("select...")
            rl, wl, xl = select([o_c, e_c], [i_c], [i_c, o_c, e_c], 1.0)
            l.debug("results - r %s w %s x %s", repr(rl), repr(wl), repr(xl))
            if i_c in wl:
                l.debug("writing allowed")
                buf = i_buf.read(1)
                if len(buf) == 0:
                    o.close()
                    o_c.shutdown_write()
                o.write(buf)
            if o_c in rl:
                l.debug("reading stdout")
                o_buf.write(o.read(BUF_SIZE))
            if e_c in rl:
                l.debug("reading stderr")
                e_buf.write(e.read(BUF_SIZE))

        # all done!

        return o_buf, e_buf

    def pipe_through_filter1(self, command, i_buf):
        """
        pipe input through a UNIX pipe on the remote end,
        returning the result
        """
        # prepare for continuous feeding
        o_buf = BytesIO()
        e_buf = BytesIO()
        i_event = Event()
        o_event = Event()
        e_event = Event()

        # run the command
        i, o, e = self.exec_command(command)

        # feed input, read from outputs
        Thread(name="out", target=_feed_file,
               args=(o, o_buf, o_event)).start()
        Thread(name="err", target=_feed_file,
               args=(e, e_buf, e_event)).start()
        Thread(name="in", target=_feed_file,
               args=(i_buf, i, i_event, True)).start()

        # wait for them to finish
        while not o.channel.exit_status_ready():
            i_event.wait(1.0)
            o_event.wait(1.0)
            e_event.wait(1.0)
            if i_event.is_set() and o_event.is_set() and e_event.is_set():
                break

        # all done!

        return o_buf, e_buf

    def pipe_through_filter(self, command, i_buf):
        """
        pipe input through a UNIX pipe on the remote end,
        returning the result
        """
        # prepare for continuous feeding
        o_buf = BytesIO()
        e_buf = BytesIO()
        i_event = Event()
        o_event = Event()
        e_event = Event()

        # run the command
        transport = self.get_transport()
        chan = transport.open_session()
        chan.exec_command(command)

        # feed input, read from outputs
        Thread(name="out", target=_chan_receiver,
               args=(chan.recv, o_buf, o_event)).start()
        Thread(name="err", target=_chan_receiver,
               args=(chan.recv_stderr, o_buf, o_event)).start()
        Thread(name="in", target=_chan_sender,
               args=(i_buf, chan, i_event)).start()

        # wait for them to finish
        while not chan.exit_status_ready():
            i_event.wait(1.0)
            o_event.wait(1.0)
            e_event.wait(1.0)
            if i_event.is_set() and o_event.is_set() and e_event.is_set():
                break

        return o_buf, e_buf, chan.recv_exit_status()


def main():
    """test"""
    host = 'syd.secauth.net'
    user = 'root'
    key_file = '/home/tech/.ssh/id_rsa'
    hosts_file = '/home/tech/syd_known_hosts'

    client = DBSSHClient()
    client.load_host_keys(hosts_file)
    client.set_missing_host_key_policy(AutoAddPolicy)
    client.connect(hostname=host, username=user, key_filename=key_file)

    i_buf = BytesIO(b"the quick brown fox jumped over the lazy dog \n" * 999)
    o, e = client.pipe_through_filter('cat', i_buf)

    print("Output", o.getvalue().decode('utf-8'))
    print("Error", e.getvalue().decode('utf-8'))

#    i, o, e = client.exec_command('c')
#    i.close()
#    while True:
#        line = o.readline()
#        if not line:
#            break
#        print(line[:-1])
#    o.close()
#    e.close()
#    client.close()

if __name__ == '__main__':
    main()
