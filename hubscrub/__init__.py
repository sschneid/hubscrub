from threading import Thread
import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
logger.propagate = False
formatter = logging.Formatter('[%(asctime)s] %(message)s')

fh = logging.FileHandler('/tmp/hubscrub.log', 'w')
fh.setLevel(logging.DEBUG)
fh.setFormatter(formatter)
logger.addHandler(fh)

keep_fds = [fh.stream.fileno()]

from flask import Flask
app = Flask(__name__)

app.logger.addHandler(fh)

from hubscrub.scan import start_periodic_scan
start_periodic_scan()

import hubscrub.views
