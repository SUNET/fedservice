FROM python:3.12-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    python3-dev \
    build-essential \
    python3-pip \
    libffi-dev \
    libssl-dev \
    xmlsec1 \
    libyaml-dev \
    jq
RUN pip3 install --upgrade pip setuptools
COPY . /fedservice
RUN pip3 install -r fedservice/docker/requirements.docker
RUN pip3 install /fedservice
COPY docker/start.sh .
ENTRYPOINT ["/start.sh"]
#RUN cp /src/fedservice/setup_federation/entity.py /
#RUN sed -e "s@'templates'@'data/templates'@" -e "s@sys.path.insert(0, dir_path)@sys.path.insert(0, dir_path)\n    app.config['SECRET_KEY'] = os.urandom(12).hex()@" /src/fedservice/setup_federation/entity.py > /entity.py && \
#        chmod u+x /entity.py

