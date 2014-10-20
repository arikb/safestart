'''
Platform specific classes
'''

from fnmatch import translate as fnmatch_translate
from gzip import GzipFile
from io import BytesIO
import re

import log
l = log.getLogger(__name__)


class Ubuntu_14_04:

    PIPE_NAME = "/lib/cryptsetup/passfifo"
    SUM_PROGRAM_LOCAL = '/usr/bin/sha256sum'
    SUM_PROGRAM_REMOTE = '/root/file_sum'
    PASSWORD_SCRIPT_REMOTE = '/root/pass_script'
    SUM_COMMAND = ('find / -type f -xdev -exec {0} {{}} \; '
                   '| gzip').format(SUM_PROGRAM_REMOTE).encode('ascii')
    SCRIPT_EXEC_COMMAND = '. {}'.format(PASSWORD_SCRIPT_REMOTE)
    EXCLUDE_FILES = (
        '*.pid',
        SUM_PROGRAM_REMOTE,
        )
    EXCLUDE_PATTERNS = [re.compile(fnmatch_translate(g).encode('ascii'))
                        for g in EXCLUDE_FILES]
    EXCLUDE_PATTERN = re.compile(('(' + '|'.join([fnmatch_translate(g)
                                                  for g
                                                  in EXCLUDE_FILES]
                                                 ) + ')').encode('ascii'))

    PASSWORD_ENTRY_SCRIPT = """
echo 'Stopping plymouth...'
plymouth --wait quit
echo 'Waiting for plymouth to stop and the cryptosetup to restart...'
while [ ! -p {pipe_name} ]; do
    sleep 1
    echo 'Still waiting...'
done
echo 'Ready for password entry, taking the network down'
sleep 2
ip address del {ip_address} dev {dev}
ip link set dev {dev} down
echo -ne '{password}' > {pipe_name}
exit
"""

    CMD_IP_ADDR_LIST = 'ip address list'
    INET_MATCH = re.compile(r'\s*inet\s(?P<ip>[^\s]*)'
                            r'.*\s+(?P<dev>[^\s]+)').match

    @classmethod
    def get_remote_sums(cls, client):
        '''returns a file object containing a hash\tfilename\n database'''
        l.debug("Copying over sum program")
        client.send_file(cls.SUM_PROGRAM_LOCAL, cls.SUM_PROGRAM_REMOTE)
        client.chmod(cls.SUM_PROGRAM_REMOTE, "755")
        # get the result of running the checksum on all regular files
        l.debug("Applying sum to regular files")
        cmd = cls.SUM_COMMAND

        (o_buf, e_buf, exit_code) = client.exec_command_output_only(cmd)
        # delete sum program
        client.rm(cls.SUM_PROGRAM_REMOTE)

        # error checking
        if not exit_code == 0:
            l.error("Could not retrieve sums. Error: %s",
                    e_buf.getvalue().decode('utf-8'))
            return None

        # wrap the file in a zip object to unzip
        o_buf.seek(0)
        unzipped_out = GzipFile(fileobj=o_buf)

        return unzipped_out

    @classmethod
    def _get_ip_and_dev(cls, client):
        '''
        detect the IP address of the remote machine (including netmask) and the
        device it's on
        '''

        (out_f,
         _err,
         ret_code) = client.exec_command_output_only(cls.CMD_IP_ADDR_LIST)

        if ret_code > 0:
            l.error("Failed to retreive remote IP / dev")
            return None, None

        # parse the output
        out_f.seek(0)
        for line in out_f:
            match = cls.INET_MATCH(line.decode('utf-8'))
            if match:
                ip = match.group('ip')
                dev = match.group('dev')
                if dev != 'lo':  # any IP address that's not loopback
                    break
        else:
            l.error("No IP address found")
            return None, None

        return ip, dev

    @classmethod
    def enter_password(cls, client, password):
        l.debug("getting the IP address and device")
        ip, dev = cls._get_ip_and_dev(client)
        if ip is None:
            l.error("Could not retrieve remote IP / device")
            return False

        l.debug("Creating and running the password entry script")

        script = cls.PASSWORD_ENTRY_SCRIPT.format(ip_address=ip,
                                                  dev=dev,
                                                  password=password,
                                                  pipe_name=cls.PIPE_NAME)

        client.send_file_obj(BytesIO(script.encode('utf-8')),
                             cls.PASSWORD_SCRIPT_REMOTE)
        (out_f,
         _err_f,
         _ret_code) = client.exec_command_output_only(cls.SCRIPT_EXEC_COMMAND)

        l.debug("Password entry script complete.")

        for line in out_f:
            l.debug('Remote said: %s', line.decode('utf-8'))

        return True
