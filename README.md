#safestart
==========

Enter the password of cryptosetup remotely in Ubuntu 14.04 Server (for now).

## How to use it:

`python safestart.py [conf=config-file] [known_hosts=known-hosts-database] [update]`

*tested with Python 3.2*

`conf` - specifies the configuration file, defaults to safestart.conf in the
         current directory

`known_hosts` - specifies the known hosts database file, openssh format

`update` - updates the tripwire database from the server


## What it does

1. Connects to the remote server, using the standard add-if-not-found strategy
   for checking the remote public key

2. Copies a checksum program over to the remote server

3. Calculates checksums for all regular files

4. Compares the checksums to the tripwire database

5. If the checksums match the database, copies and runs a script that decrypts
   the encrypted filesystems

