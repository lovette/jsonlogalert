FROM docker.io/library/debian:latest

RUN set -eux; \
	apt-get update; \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends man python3 python3-venv python3-systemd; \
    rm -rf /var/lib/apt/lists/*

COPY . /opt/jsonlogalert

WORKDIR /opt/jsonlogalert

RUN set -eux; \
    mkdir /tmp/pycache; \
    chmod o-rwx /tmp/pycache

ENV PYTHONPYCACHEPREFIX=/tmp/pycache

RUN set -eux; \
    make virtualenv

ENV VIRTUAL_ENV=/root/.virtualenvs/jsonlogalert
ENV PATH="$VIRTUAL_ENV/bin:$PATH"

RUN set -eux; \
    make install

ENTRYPOINT ["python3", "jsonlogalert.py"]
