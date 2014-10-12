"""
    DBSSHClient is a class that extends the paramiko SSHClient with some
    advanced remote command execution and simulated file transfer for
    dropbear (which would otherwise be done using SFTP or SCP).

    Usage:

    host = 'host.example.com'
    user = 'root'
    key_file = 'id_rsa'
    hosts_file = 'my_known_hosts'

    client = DBSSHClient()
    client.load_host_keys(hosts_file)
    client.set_missing_host_key_policy(AutoAddPolicy)
    client.connect(hostname=host, username=user, key_filename=key_file)

    client.send_file('xxx', 'yyy')
    client.receive_file('xxx', 'yyy')
"""

from io import BytesIO
from threading import Event, Thread
from time import time

from paramiko.client import (SSHClient,
                             AutoAddPolicy,
                             RejectPolicy,
                             WarningPolicy)

import log
l = log.getLogger(__name__)

BUF_SIZE = 512

# avoid PEP8 "imported but unused" warning
assert AutoAddPolicy
assert RejectPolicy
assert WarningPolicy


class DBSSHClient(SSHClient):
    """
    an SSH client, but with emulated file transfer to get over DropBear
    limitations
    """

    def pipe_through_filter(self, command, i_buf, o_buf=None, e_buf=None):
        """
        pipe input through a UNIX pipe on the remote end,
        returning the result
        """
        # prepare for continuous feeding
        if o_buf is None:
            o_buf = BytesIO()
        if e_buf is None:
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
            l.debug("sending to channel...")
            _blocking_loop(source.read, chan.sendall)
            l.debug("shutting channel write side")
            chan.shutdown_write()
            source.close()
            event.set()

        def _chan_receiver(chan_recv, dest, event):
            """receive what we can from a channel until EOF"""
            l.debug("Receiving from channel...")
            _blocking_loop(chan_recv, dest.write)
            l.debug("EOF encountered")
            event.set()

        # run the command
        transport = self.get_transport()
        chan = transport.open_session()
        chan.exec_command(command)

        # feed input, read from outputs
        l.debug("new threads go!")
        Thread(name="out", target=_chan_receiver,
               args=(chan.recv, o_buf, o_event)).start()
        Thread(name="err", target=_chan_receiver,
               args=(chan.recv_stderr, o_buf, o_event)).start()
        Thread(name="in", target=_chan_sender,
               args=(i_buf, chan, i_event)).start()

        # wait for them to finish
        start_time = time()
        while not chan.exit_status_ready():
            i_event.wait(1.0)
            o_event.wait(1.0)
            e_event.wait(1.0)
            if i_event.is_set() and o_event.is_set() and e_event.is_set():
                break
            l.debug("waiting %.3f seconds so far...", time() - start_time)

        l.debug("execution time - %.3f seconds", time() - start_time)

        return o_buf, e_buf, chan.recv_exit_status()

    def exec_command_output_only(self, command, o_buf=None, e_buf=None):
        """
        run a command that has no input, returning stdout, stderr and
        the exit code
        """
        # basically pipe the command with no input
        return self.pipe_through_filter(command, BytesIO(), o_buf, e_buf)

    def exec_command_input_only(self, command, i_buf):
        """
        run a command and discard the output
        """
        _o_buf, _e_buf, exit_code = self.pipe_through_filter(command, i_buf)
        return exit_code

    def exec_command_no_io(self, command):
        """
        run a command without any input and discard the output
        """
        _o_buf, _e_buf, exit_code = self.pipe_through_filter(command,
                                                             BytesIO())
        return exit_code

    def send_file(self, local_path, remote_path):
        """
        Simulate file transfer using 'cat' on the remote end
        """
        command = "cat > {0}".format(remote_path)
        with open(local_path, 'rb') as local_file:
            exit_code = self.exec_command_input_only(command, local_file)
        return (exit_code == 0)

    def receive_file(self, remote_path, local_path):
        """
        Simulate file transfer using 'cat' on the remote end
        """
        command = "cat < {0}".format(remote_path)
        with open(local_path, 'wb') as local_file:
            (_o_buf,
             _e_buf,
             exit_code) = self.exec_command_output_only(command,
                                                        local_file)
        return (exit_code == 0)

    def chmod(self, path, mode):
        """change the mode of the file. mode is a string."""
        command = "chmod {0} {1}".format(mode, path)
        exit_code = self.exec_command_no_io(command)
        return (exit_code == 0)

    def rm(self, path):
        """remove a path"""
        command = "rm -f {0}".format(path)
        exit_code = self.exec_command_no_io(command)
        return (exit_code == 0)

    def file_exists(self, path):
        """returns True if the file exists"""
        command = "ls {0}".format(path)
        exit_code = self.exec_command_no_io(command)
        return (exit_code == 0)
