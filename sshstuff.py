"""do some useful things over SSH"""

from io import BytesIO
import paramiko
import socket  # mainly for socket errors


import log
l = log.getLogger(__name__)


class SSHConnection:
    "an SSH connection, doing what we need at a higher level"

    COPY_BUFFER_SIZE = 512

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
        self._sftp_session = None

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

    def execute_command(self, command, sensitive=False):
        """
        Execute the `command` and return its return code, stdout and stderr.

        If the command is `sensitive`, the command itself will not be logged.
        """
        # for logging. Trenary operator seems like it would be perfect here.
        logged_command = "[redacted]" if sensitive else command

        # must have a transport first
        transport = self.get_transport()

        # get a session channel and run the command inside
        chan = transport.open_session()
        chan.set_name('command: ' + logged_command)
        chan.setblocking(True)
        chan.settimeout(10.0)

        # and finally
        chan.exec_command(command)

        # wait for the command to terminate
        try:
            exit_status = chan.recv_exit_status()
        except socket.timeout:
            l.error("Socket timeout when executing command %s", logged_command)
            return (None, None, None)

        if exit_status > 0:
            l.warning("Command %s returned exit status %d",
                      logged_command, exit_status)
        # get stdout, stderr if available
        stdout_buf = BytesIO()
        stderr_buf = BytesIO()
        while chan.recv_ready():
            stdout_buf.write(chan.recv(self.COPY_BUFFER_SIZE))
        while chan.recv_stderr_ready():
            stderr_buf.write(chan.recv_stderr(self.COPY_BUFFER_SIZE))
        chan.close()

        return exit_status, stdout_buf, stderr_buf

    def _get_sftp_session(self):
        """returns an SFTP session to the server, creating it if needed"""
        if self._sftp_session is None:

            # must have a transport first
            transport = self.get_transport()

            # get a session channel and run the command inside
            chan = transport.open_sftp_client()
            chan.setblocking(True)
            chan.settimeout(10.0)
            self._sftp_session = chan

        return self._sftp_session

    def copy_local_to_remote(self, local, remote):
        """ copy the `local` file to the `remote` path"""

        l.debug("Copying (local)%s --> (remote)%s", local, remote)

        sftp_session = self._get_sftp_session()
        sftp_session.put(local, remote)

        return True

    def copy_remote_to_local(self, remote, local):
        """ copy the `remote` file to the `local` path"""

        l.debug("Copying (remote)%s --> (local)%s", remote, local)

        sftp_session = self._get_sftp_session()
        sftp_session.get(remote, local)

        return True

