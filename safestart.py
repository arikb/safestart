'''

'''

from fnmatch import translate as fnmatch_translate
from gzip import GzipFile
import os
import re
import sys
from time import sleep

from sshstuff import DBSSHClient, AutoAddPolicy

import log
l = log.getLogger(__name__)


def parse_database(db_file):
    """
    parse a database made of lines in the form:

    {file_sum}{whitespace}{file_name}{EOL}

    returning a list of file names and a mapping of file_name --> file_sum
    """
    name_map = dict()
    names = list()
    for line in db_file:
        file_sum, file_name = line.strip().split()
        name_map[file_name] = file_sum
        names.append(file_name)

    return names, name_map


def write_database(db_file, names, name_map):
    """
    writes to the file a database in the form:

    {file_sum}{tab}{file_name}{EOL}

    from the list of names in order, receiving file_sum from name_map
    """
    for name in names:
        db_file.write(name_map[name] + b'\t' + name + b'\n')
    return


def compare_databases(names, name_map, db_names, db_name_map):
    """Compare the database to the received names"""
    diff = list()
    idx, db_idx = 0, 0
    size, db_size = len(names), len(db_names)

    # assuming both names and db_names are sorted for an O(n) comparison
    # (but paid O(log n) to do the sorting)
    while (idx < size) and (db_idx < db_size):
        name, db_name = names[idx], db_names[db_idx]
        if name == db_name:
            if name_map[name] != db_name_map[db_name]:
                diff.append(('U', name))
            idx += 1
            db_idx += 1
        elif name > db_name:
            diff.append(('D', db_name))
            db_idx += 1
        else:
            diff.append(('A', name))
            idx += 1
    while (idx < size):
        name = names[idx]
        diff.append(('A', name))
        idx += 1
    while (db_idx < db_size):
        db_name = db_names[db_idx]
        diff.append(('D', db_name))
        db_idx += 1

    return diff


# a UNIX find on the remote host that returns the checksum of all regular files
# in the root filedsystem
SUM_PROGRAM_LOCAL = '/usr/bin/sha256sum'
SUM_PROGRAM_REMOTE = '/root/file_sum'
SUM_COMMAND = ('find / -type f -xdev -exec {0} {{}} \; '
               '| gzip').format(SUM_PROGRAM_REMOTE).encode('ascii')
EXCLUDE_FILES = (
    '*.pid',
    SUM_PROGRAM_REMOTE,
    )
EXCLUDE_PATTERNS = [re.compile(fnmatch_translate(g).encode('ascii'))
                    for g in EXCLUDE_FILES]


def get_sums_from_remote(client):
    """get the file checksums from the remote server"""

    l.debug("Copying over sum program")
    client.send_file(SUM_PROGRAM_LOCAL, SUM_PROGRAM_REMOTE)
    client.chmod(SUM_PROGRAM_REMOTE, "755")
    # get the result of running the checksum on all regular files
    l.debug("Applying sum to regular files")
    o_buf, e_buf, exit_code = client.exec_command_output_only(SUM_COMMAND)

    # error checking
    if not exit_code == 0:
        l.error("Could not retrieve sums. Error: %s", repr(e_buf.getvalue()))
        return None, None

    # wrap the file in a zip object to unzip
    o_buf.seek(0)
    unzipped_out = GzipFile(fileobj=o_buf)

    l.debug("Parsing the results")
    names, name_map = parse_database(unzipped_out)
    names.sort()

    l.debug("Removing excluded names")
    clean_names = list()
    for name in names:
        if any([pat.match(name) for pat in EXCLUDE_PATTERNS]):
            del name_map[name]
        else:
            clean_names.append(name)

    return clean_names, name_map

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


def main(args):
    """do it"""
    # first SSH and do a checksum
    host = 'syd.secauth.net'
    user = 'root'
    key_file = '/home/tech/.ssh/id_rsa'
    hosts_file = '/home/tech/syd_known_hosts'

    client = DBSSHClient()
    client.load_host_keys(hosts_file)
    client.set_missing_host_key_policy(AutoAddPolicy)
    client.connect(hostname=host, username=user, key_filename=key_file)

    # get the sums from the server
    names, name_map = get_sums_from_remote(client)
    if names is None:
        l.error("Error receiving remote sums")
        return

    db_filename = '{}.tripwire.db'.format(host)

    if UPDATE in args:
        # update / create the database file
        if os.path.exists(db_filename):
            l.info("Updating database file %s", db_filename)
        else:
            l.info("Creating database file %s", db_filename)

        with open(db_filename, 'wb') as db_file:
            write_database(db_file, names, name_map)
        return

    l.debug("Reading database")
    if not os.path.exists(db_filename):
        l.error("Database file %s doesn't exist", db_filename)
        return

    with open(db_filename, 'rb') as db_file:
        db_names, db_name_map = parse_database(db_file)

    l.debug("Comparing remote sums to database")
    diff = compare_databases(names, name_map, db_names, db_name_map)
    if len(diff) == 0:
        l.debug("Compare successful")
    else:
        l.error("Compare failed, differences to follow")
        for action, file_name in diff:
            l.error("%s %s", action, file_name)
        return

    l.debug("asking plymouth kindly to stop")
    client.exec_command_no_io("plymouth --wait quit")
    while not client.file_exists('/lib/cryptsetup/passfifo'):
        l.debug("waiting for the fifo to be created")
        sleep(1.0)
    l.debug("piping the password into passfifo")
    client.exec_command_no_io("echo -ne '{}' > /lib/cryptsetup/passfifo".format(args['pass']))


if __name__ == '__main__':
    args = parse_arguments(sys.argv[1:])
    print(repr(args))
    main(args)
