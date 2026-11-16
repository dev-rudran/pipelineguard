# Intentionally insecure Dockerfile used by pipelineguard tests and demos.
FROM python:latest

ARG DB_PASSWORD=CDOOQygfvApVThY1gcvNQUl1gozO
ENV API_TOKEN=XSx1laLMShaSaLqM6hmdpzV8kouDWOfcL7wk

RUN apt-get update && apt-get install -y curl && curl -fsSL https://example.com/install.sh | sh

ADD https://example.com/tool.tar.gz /opt/tool.tar.gz
RUN chmod 777 /opt

WORKDIR /app
COPY . .

CMD ["python", "app.py"]
