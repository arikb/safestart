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


class DBSSHClient(SSHClient):
    """
    an SSH client, but with emulated file transfer to get over DropBear
    limitations
    """

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

        def _blocking_loop(source_fun, dest_fun):
            """main copy loop for a blocking copy"""
            while True:
                buf = source_fun(BUF_SIZE)
                if len(buf) == 0:
                    break
                dest_fun(buf)

        def _chan_sender(source, chan, event):
            """
            send everything in the buffer to the channel
            then shut sending down
            """
            _blocking_loop(source.read, chan.sendall)
            l.debug("shutting channel write side")
            chan.shutdown_write()
            source.close()
            event.set()

        def _chan_receiver(chan_recv, dest, event):
            """receive what we can from a channel until EOF"""
            _blocking_loop(chan_recv, dest.write)
            l.debug("EOF encountered, closing destination")
            event.set()

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

    def exec_command_output_only(self, command):
        """
        run a command that has no input, returning stdout, stderr and
        the exit code
        """
        # basically pipe the command with no input
        return self.pipe_through_filter(command, BytesIO())

    def exec_command_input_only(self, command, i_buf):
        """
        run a command and discard the output
        """
        _o_buf, _e_buf, exit_code = self.pipe_through_filter(command, i_buf)
        return exit_code


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

    # i_buf = BytesIO(b"the quick brown fox jumped over the lazy dog \n" * 999)
    i_buf = BytesIO()
    o, e, exit_status = client.pipe_through_filter('cat < xxx', i_buf)

    print("Output", o.getvalue().decode('utf-8'))
    print("Error", e.getvalue().decode('utf-8'))
    print("Exit status", exit_status)

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
