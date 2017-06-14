FROM python:3.6.1

RUN apt-get update
RUN apt-get install -y libxmlsec1-dev
RUN apt-get install -y redis-server

WORKDIR /opt/hubscrub

COPY requirements.txt /opt/hubscrub/requirements.txt
RUN pip3 install -r requirements.txt

COPY . /opt/hubscrub

ENTRYPOINT \
    /etc/init.d/redis-server start \
    && cd /opt/hubscrub \
    && FLASK_APP=hubscrub python -m flask run --host='0.0.0.0' \
    && while [ ! -f /tmp/hubscrub.log ]; do sleep 1; done; \
    tail -f /tmp/hubscrub.log
