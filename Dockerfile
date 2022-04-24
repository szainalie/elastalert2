FROM python:3-slim-buster
COPY . /tmp/elastalert
RUN cd /tmp/elastalert && \
 apt-get update && apt-get install -y python3-pip && \
    pip install -U --upgrade --no-cache-dir pip wheel setuptools \
    && pip install -U --no-cache-dir --disable-pip-version-check -r requirements.txt && \
 pip install setuptools wheel && python setup.py sdist bdist_wheel && \
 python setup.py install sdist bdist_wheel 
 ARG GID=1000
ARG UID=1000
ARG USERNAME=elastalert

RUN echo "#!/bin/sh" >> /tmp/elastalert/run.sh && \
    echo "set -e" >> /tmp/elastalert/run.sh && \
    echo "elastalert-create-index --config /tmp/elastalert/config.yaml" \
        >> /tmp/elastalert/run.sh && \
    echo "elastalert --config /tmp/elastalert/config.yaml \"\$@\"" \
        >> /tmp/elastalert/run.sh && \
    chmod +x /tmp/elastalert/run.sh && \
    groupadd -g ${GID} ${USERNAME} && \
    useradd -u ${UID} -g ${GID} -M -b /opt -s /sbin/nologin \
        -c "ElastAlert 2 User" ${USERNAME}
USER ${USERNAME}
ENV TZ "UTC"

WORKDIR /tmp/elastalert
ENTRYPOINT ["/tmp/elastalert/run.sh"]

