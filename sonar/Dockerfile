FROM frolvlad/alpine-python2

WORKDIR /app

ADD . /app
RUN pip install  -r /app/requirements.txt

EXPOSE 9118
CMD ["/usr/bin/python", "/app/sonar_exporter.py"]
