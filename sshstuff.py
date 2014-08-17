"""do some useful things over SSH"""

from io import BytesIO
import paramiko
import socket  # mainly for socket errors
import select
from time import sleep

import log
l = log.getLogger(__name__)

COMMAND_TERMINATION_MARKER = '--- SHELL COMMAND END ---'


class SSHConnection:
    "an SSH connection, doing what we need at a higher level"

    def __init__(self, host_id, dest, known_hosts_file, username, key_file,
                 password=None):
        """Initialises but does not connect

        `host_id` - a hostname for identifying the key
        `dest` - where to actually connect to. Can be:
            a hostname (or IP address)
            a host:port string
            a (host,port) tuple
            an open socket
        `known_hosts_file` - the known_hosts file that we use to verify the
            remote key
        `username` - the username for authentication
        `key_file` - private key file for user auth
        `password` - private key file password

        """

        # parameters
        self._host_id = host_id
        self._dest = dest
        self._known_hosts_file = known_hosts_file
        self._username = username
        self._key_file = key_file
        self._password = password

        # Internal state
        self._connected = False
        self._transport = None

    def _hostkey_verify(self):
        """
        Use known hosts to verify the remote host with the local hosts file
        and update it
        """

        # create and load the host keys object
        host_keys = paramiko.HostKeys()
        try:
            host_keys.load(self._known_hosts_file)
        except IOError:
            l.info("Could not load host keys file %s",
                   self._known_hosts_file, exc_info=True)

        # check server's host key
        host_key = self._transport.get_remote_server_key()
        if host_keys.check(self._host_id, host_key):
            l.info("Remote host key has been recognised")
        elif (host_keys.lookup(self._host_id) and
              host_keys.lookup(host_key.get_name())):
            # the key is there but it didn't check out - danger!
            l.error("Host key for host %s has changed!", self._host_id)
            return False  # that's the only reason to fail here
        else:
            l.info("Host key for host %s was not found; adding.",
                   self._host_id)
            host_keys.add(self._host_id, host_key.get_name(), host_key)
            try:
                host_keys.save(self._known_hosts_file)
            except IOError:
                l.warn("Hosts file %s cannot be written",
                       self._known_hosts_file, exc_info=True)

        return True

    def connect(self):
        """connect to the remote host"""
        if self._connected:
            return True

        try:
            l.debug("Initialising a transport to the destination")
            self._transport = paramiko.Transport(self._dest)
            l.debug("Starting the client")
            self._transport.start_client()
        except paramiko.SSHException:
            l.error("SSH negotiation failed")
            return False
        except socket.error:
            l.error("Socket connection failure")
            return False

        # verify the host
        l.debug("Verifying host key")
        if not self._hostkey_verify():
            return False

        # authenticate
        l.debug("Authenticating as %s@%s",
                self._username, self._host_id)
        if not self._rsa_key_auth():
            l.error("Authentication failed for user %s@%s",
                    self._username, self._host_id)
            return False

        l.info("Successfully connected as %s@%s",
               self._username, self._host_id)
        # success!
        self._connected = True
        return True

    def get_transport(self):
        """return an SSH transport, even if not connected"""
        if not self._connected:
            if not self.connect():
                l.error('Connection failed')
                return None
        # sanity check
        if self._connected:
            return self._transport
        return None

    def _rsa_key_auth(self):
        """authenticate to the destination with an RSA key from a key file"""
        private_key = paramiko.RSAKey.from_private_key_file(self._key_file,
                                                            self._password)
        try:
            self._transport.auth_publickey(self._username, private_key)
        except paramiko.AuthenticationException:
            l.error("Failed to authenticate.", exc_info=True)
            return False
        return self._transport.is_authenticated()

    def execute_command(self, command):
        """
        Execute the `command` and return its return code, stdout and stderr.
        """
        # must have a transport first
        transport = self.get_transport()

        # get a session channel and run the command inside
        chan = transport.open_session()
        chan.set_name('command:' + command)
        chan.setblocking(True)
        chan.settimeout(10.0)
        chan.exec_command(command)

        # wait for the command to terminate
        try:
            exit_status = chan.recv_exit_status()
        except socket.timeout:
            return (None, None, None)

        # get stdout, stderr if available
        stdout_buf = BytesIO()
        stderr_buf = BytesIO()
        while chan.recv_ready():
            stdout_buf.write(chan.recv(512))
        while chan.recv_stderr_ready():
            stderr_buf.write(chan.recv_stderr(512))
        chan.close()

        return exit_status, stdout_buf, stderr_buf

