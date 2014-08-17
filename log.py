"""
a logger module that would produce logs at varying levels.

Usage:

# init
import log
l=log.getLogger(__name__)

# usage
l.debug("Module starting")
l.error("Error occured!")
l.info("Statistics: %02f",stat_val)

"""

from logging import getLogger
from logging.config import fileConfig
import os
import re
from io import StringIO
import sys

# and our own config file section
LOG_CONFIG_TEMPLATE_FILE = 'log.ini'
log_file_path_re = re.compile(r'LOG_FILE_PATH')
EMERGENCY_LOGGER = StringIO("""
[loggers]
keys: root

[handlers]
keys: stderr

[formatters]
keys: std

[logger_root]
level: DEBUG
handlers: stderr

[handler_stderr]
class: StreamHandler
formatter: std
level: NOTSET
args: (sys.stderr, )

[formatter_std]
format: %(asctime)s %(levelname)s %(module)s:%(lineno)d %(message)s
datefmt: %Y-%b-%d %H:%M:%S
""")

LOG_FILE_NAME = "safestart.log"

# Initialise the logging subsystem
# locate the configuration file in the folder we run from
my_path = os.path.split(sys.argv[0])[0]
conf_template_file = os.path.join(my_path, LOG_CONFIG_TEMPLATE_FILE)
log_file_path = os.path.join(my_path, LOG_FILE_NAME)
emergency_logging = False

if os.path.exists(conf_template_file) and log_file_path is not None:
    # modify the configuration file in memory
    # add the configured target file to the file
    new_config = StringIO()
    template_file = open(conf_template_file, 'rt')
    log_file_abspath = os.path.abspath(log_file_path)
    for line in template_file:
        new_config.write(log_file_path_re.sub(repr(log_file_abspath), line))
    # rewind the memory file in preparation for using it as a
    # configuration file
    new_config.seek(0)
    fileConfig(new_config)
else:
    # couldn't find the file,but we can still work
    emergency_logging = True
    fileConfig(EMERGENCY_LOGGER)

# we deserve our own logger!
l = getLogger(__name__)
if emergency_logging:
    l.warning("Logging configuration file not found. "
              "Logging to STDOUT only")
l.info('Logging subsystem initialised')
