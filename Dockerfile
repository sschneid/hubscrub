FROM python:3.6.1

WORKDIR /opt/hubscrub

RUN apt-get update \
    && apt-get install -y libxmlsec1-dev redis-server

# Copy and install requirements.txt separately
# for more efficient image build caching.
COPY requirements.txt /opt/hubscrub/requirements.txt
RUN pip3 install -r requirements.txt

ADD https://github.com/Yelp/dumb-init/releases/download/v1.2.0/dumb-init_1.2.0_amd64 /bin/dumb-init
COPY . /opt/hubscrub
RUN chmod +x /opt/hubscrub/startup /bin/dumb-init

ENTRYPOINT [ "/bin/dumb-init", "--" ]
CMD ["/opt/hubscrub/startup"]

EXPOSE 5000
