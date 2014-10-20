'''

'''

from collections import namedtuple
from configparser import ConfigParser
import os
import sys

import platforms
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


UPDATE = 'update'
SKIP = 'skip-sums'
CONFIG = 'conf'
DEFAULT_CONFIG = 'safestart.conf'
DEFAULT_USER = 'root'
HOST_FIELD = 'host'
USER_FIELD = 'username'
KEYFILE_FIELD = 'key_file'
PLATFORM_FIELD = 'platform'
PASSWORD_FIELD = 'password'
KNOWN_HOSTS = 'known_hosts'
DEFAULT_KNOWN_HOSTS = 'known_hosts.db'

HostConfig = namedtuple(typename='HostConfig',
                        field_names=[HOST_FIELD,
                                     USER_FIELD,
                                     KEYFILE_FIELD,
                                     PLATFORM_FIELD,
                                     PASSWORD_FIELD])


def load_config_file(args):
    '''load data from a configuration file'''
    config_file = 'safestart.conf'
    if CONFIG in args:
        config_file = args[CONFIG]

    conf = ConfigParser()
    conf.read(config_file)
    # every section is a host
    hosts = list()
    for section in conf.sections():
        host = section
        username = conf.get(section, USER_FIELD, fallback='root')
        key_file = conf.get(section, KEYFILE_FIELD)
        platform = getattr(platforms, conf.get(section, PLATFORM_FIELD))
        password = conf.get(section, PASSWORD_FIELD)
        hosts.append(HostConfig(host, username, key_file, platform, password))

    return hosts


def known_hosts(args):
    '''return the known hosts file'''
    if KNOWN_HOSTS in args:
        return args[KNOWN_HOSTS]
    else:
        return os.path.abspath(DEFAULT_KNOWN_HOSTS)


def main(args):
    '''do it'''
    # get some configuration going
    hosts_file = known_hosts(args)
    hosts_config = load_config_file(args)

    # do for all hosts
    for host_config in hosts_config:
        client = DBSSHClient()
        if os.path.exists(hosts_file):
            client.load_host_keys(hosts_file)
        client.set_missing_host_key_policy(AutoAddPolicy())
        client.connect(hostname=host_config.host,
                       username=host_config.username,
                       key_filename=host_config.key_file)
        client.save_host_keys(hosts_file)

        if SKIP in args:
            l.info("Skipping tripwire checks")
        else:
            twdb = TripwireDatabase(client, host_config.host,
                                    host_config.platform)
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

        host_config.platform.enter_password(client, host_config.password)
        client.close()


if __name__ == '__main__':
    args = parse_arguments(sys.argv[1:])
    main(args)
