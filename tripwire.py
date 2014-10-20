'''

This tripwire modules is named after the once-popular "tripwire" from 1992,
later on to form the basis for Tripwire, Inc.

It runs a simple command on the remote server requesting the list of files
and their cryptographic hashes, and maintains a database of previous requests
so that any change can be easily detected.

'''

import os

import log
l = log.getLogger(__name__)


DB_FILENAME_PATTERN = '{}.tripwire.db'


def _parse_database(db_file):
    '''
    parse a database made of lines in the form:

    {file_sum}{whitespace}{file_name}{EOL}

    returning a list of file names and a mapping of file_name --> file_sum
    '''
    name_map = dict()
    names = list()
    for line in db_file:
        file_sum, file_name = line.strip().split()
        name_map[file_name] = file_sum
        names.append(file_name)

    return names, name_map


class TripwireDatabase:
    '''
    maintain a 'tripwire' database - a list of "interesting" files and
    their hash value for future comparison
    '''
    def __init__(self, client, host, platform):
        self._ssh_client = client
        self._platform = platform
        self._host = host
        self._db_filename = DB_FILENAME_PATTERN.format(host)
        self._db_file_exists = os.path.exists(self._db_filename)
        self._remote_names = self._remote_name_map = None
        self._db_names = self._db_name_map = None

        # try to load the database into memory
        if self._db_file_exists:
            self._load_database()

    def _write_database(self):
        '''
        writes to the file a database in the form:

        {file_sum}{tab}{file_name}{EOL}

        from the list of names in order, receiving file_sum from name_map
        '''
        filename = self._db_filename
        if self._db_file_exists:
            l.info("Updating database file %s", filename)
        else:
            l.info("Creating database file %s", filename)

        with open(filename, 'wb') as db_file:
            for name in self._db_names:
                db_file.write(self._db_name_map[name] + b'\t' + name + b'\n')
        return

    def _load_database(self):
        if not self._db_file_exists:
            # no point in reading what's not there
            return
        with open(self._db_filename, 'rb') as db_file:
            self._db_names, self._db_name_map = _parse_database(db_file)
        return

    def get_remote_sums(self):
        '''get the file checksums from the remote server'''

        l.debug("Requesting remote sums")
        sums_stream = self._platform.get_remote_sums(self._ssh_client)

        l.debug("Parsing the results")
        names, name_map = _parse_database(sums_stream)
        names.sort()

        l.debug("Removing excluded names")
        clean_names = list()
        for name in names:
            if any(
                    [pat.match(name)
                     for pat
                     in self._platform.EXCLUDE_PATTERNS]
            ):
                del name_map[name]
            else:
                clean_names.append(name)

        self._remote_names = clean_names
        self._remote_name_map = name_map

    def compare_databases(self):
        '''Compare the database to the received names'''
        diff = list()
        idx, db_idx = 0, 0
        names, db_names = self._remote_names, self._db_names  # short names
        name_map, db_name_map = self._remote_name_map, self._db_name_map
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

    def update_database(self):
        '''(re)write the database file with the data from the remote server'''
        self._db_names = self._remote_names
        self._db_name_map = self._remote_name_map
        self._write_database()
