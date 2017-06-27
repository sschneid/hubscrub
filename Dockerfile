FROM python:3.6.1

RUN apt-get update
RUN apt-get install -y libxmlsec1-dev
RUN apt-get install -y redis-server

ADD https://github.com/Yelp/dumb-init/releases/download/v1.2.0/dumb-init_1.2.0_amd64 /bin/dumb-init

WORKDIR /opt/hubscrub

COPY . /opt/hubscrub
RUN pip3 install -r requirements.txt \
    && chmod +x /opt/hubscrub/startup /bin/dumb-init

ENTRYPOINT [ "/bin/dumb-init", "--" ]
CMD ["/opt/hubscrub/startup"]

EXPOSE 5000
