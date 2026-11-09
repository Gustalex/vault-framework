# Imagem única para os 4 microserviços; o serviço é escolhido por SERVICE_MODULE/SERVICE_PORT.
FROM python:3.12-slim
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
COPY pyproject.toml README.md ./
COPY vaultkit ./vaultkit
RUN pip install --no-cache-dir ".[services]"
COPY services ./services
ARG SERVICE_MODULE=services.gateway.main
ARG SERVICE_PORT=8800
ENV SERVICE_MODULE=${SERVICE_MODULE} SERVICE_PORT=${SERVICE_PORT}
EXPOSE ${SERVICE_PORT}
CMD ["sh", "-c", "uvicorn ${SERVICE_MODULE}:app --host 0.0.0.0 --port ${SERVICE_PORT}"]
