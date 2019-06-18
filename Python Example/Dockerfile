# Start from an Apline linux image with Python installed
FROM python:2.7.15-alpine
WORKDIR /app
COPY x710update.py /app
COPY goldbios.json /app
COPY requirements.txt /app
#RUN apt-get install -y python-pip libpq-dev python-dev
RUN python -m pip install --upgrade pip setuptools wheel
RUN pip install -r /app/requirements.txt