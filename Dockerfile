FROM python:3.11-alpine

WORKDIR /app

COPY dist/disclosurecheck-*.tar.gz /app/

RUN cd /app && \
    pip install disclosurecheck-*.tar.gz

ENTRYPOINT ["disclosurecheck"]
