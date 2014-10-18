'''

'''

from fnmatch import translate as fnmatch_translate
from io import BytesIO
import re
import sys
from time import sleep

from sshstuff import DBSSHClient, AutoAddPolicy
from tripwire import TripwireDatabase

import log
l = log.getLogger(__name__)


STRIP_QUOTES = "'\"\t\r\n "


def parse_arguments(arg_list):
    """returns a dictionary with parsed arguments"""

    # parse the arguments into a dictionary
    args = dict()
    eat_me = 0

    for loc, arg in enumerate(arg_list):
        # skip tokens eaten by previous iterations
        if eat_me:
            eat_me -= 1
            continue

        arg = arg.strip(STRIP_QUOTES)
        split_result = arg.split('=', 1)
        if len(split_result) == 1:  # only key found
            # deal with the cases of:
            # key =value
            # key = value
            # key (no value)

            # look ahead to the next argument
            if ((loc + 1) < len(arg_list) and
                    arg_list[loc + 1].strip(STRIP_QUOTES)[0] == '='):

                extended = arg_list[loc + 1].strip(STRIP_QUOTES)
                eat_me = 1
                if len(extended) == 1 and (loc + 2) < len(arg_list):
                    # case key = value - equal sign on it's own
                    extended += arg_list[loc + 2].strip(STRIP_QUOTES)
                    eat_me = 2
                # invariant - starts with =
                args[split_result[0]] = extended[1:]
            else:  # no value
                args[split_result[0]] = None
        else:
            # deal with the cases of:
            # key=value
            # key= value
            if len(split_result[1]):  # key=value
                args[split_result[0]] = split_result[1].strip(STRIP_QUOTES)
            else:  # key= value
                if (loc + 1) < len(arg_list):
                    args[split_result[0]] = (
                        arg_list[loc + 1].strip(STRIP_QUOTES))
                else:  # key= (no value)
                    args[split_result[0]] = ''  # blank string, as intended

    assert eat_me == 0, "Parse error - skipped arguments that do not exist?!"

    return args


PS_CMD = 'ps lw'


def get_process_list(client):
    '''run ps remotely retrieving the running processes'''
    # run PS
    out_buf, _err_buf, exit_code = client.exec_command_output_only(PS_CMD)
    if exit_code:
        l.debug("Could not enumerate remote processes")
        return None

    # parse
    out_buf.seek(0)
    headers = out_buf.readline().decode('utf-8').split()
    hnum = len(headers)
    l.debug("Process headers: %s", repr(headers))
    lines = list()
    for line in out_buf:
        lines.append(dict(zip(headers,
                              line.decode('utf-8').split(None, hnum-1)
                              )))

    return lines

UPDATE = 'update'
SKIP = 'skip-sums'


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


def main(args):
    '''do it'''
    # first SSH and do a checksum
    host = 'syd.secauth.net'
    user = 'root'
    key_file = '/home/tech/.ssh/id_rsa'
    hosts_file = '/home/tech/syd_known_hosts'
    platform = Ubuntu_14_04

    client = DBSSHClient()
    client.load_host_keys(hosts_file)
    client.set_missing_host_key_policy(AutoAddPolicy)
    client.connect(hostname=host, username=user, key_filename=key_file)

    if SKIP in args:
        l.info("Skipping tripwire checks")
    else:
        twdb = TripwireDatabase(client, host, platform)
        twdb.get_remote_sums()

        if UPDATE in args:
            twdb.update_database()
            return

        l.debug("Comparing remote sums to database")
        diff = twdb.compare_databases()
        if len(diff) == 0:
            l.debug("Compare successful")
        else:
            l.error("Compare failed, differences to follow")
            for action, file_name in diff:
                l.error("%s %s", action, file_name)
            return

    platform.enter_password(client, args['password'])


if __name__ == '__main__':
    args = parse_arguments(sys.argv[1:])
    main(args)
