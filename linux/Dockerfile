FROM python:3.11-slim

COPY requirements.txt /
RUN pip install -r /requirements.txt

COPY pipe /
COPY LICENSE pipe.yml README.md /

ENTRYPOINT ["python3", "/RunSAST.py"]
