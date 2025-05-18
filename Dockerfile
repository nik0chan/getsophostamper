FROM python:3-slim

RUN apt-get update \
    && apt-get install -y python3-pip \
    && python3 -m pip install flask \
    && python3 -m pip install requests

WORKDIR /srv/getsophostamper
COPY scripts /srv/getsophostamper
EXPOSE 5000
CMD ["python3", "/srv/getsophostamper/Sophos_Central_Get_Tamper_webservice.py"]
