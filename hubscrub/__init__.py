from threading import Thread
from time import time
import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
logger.propagate = False
formatter = logging.Formatter('[%(asctime)s] %(message)s')

# dict that gets rendered out at /api/health
# fetch/store on global dicts is thread safe due to GIL
health = {'startup': time()}

fh = logging.FileHandler('/tmp/hubscrub.log', 'w')
fh.setLevel(logging.DEBUG)
fh.setFormatter(formatter)
logger.addHandler(fh)

keep_fds = [fh.stream.fileno()]

from flask import Flask
app = Flask(__name__)

app.logger.addHandler(fh)

from hubscrub.scan import start_periodic_scans
start_periodic_scans()

import hubscrub.views
