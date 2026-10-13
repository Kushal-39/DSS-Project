FROM python:3.12-slim
WORKDIR /app
COPY account-service/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt && useradd -u 1001 gateway
COPY common /app/common
COPY gateway /app/gateway
USER 1001
EXPOSE 8080
CMD ["python", "-m", "uvicorn", "gateway.main:app", "--host", "0.0.0.0", "--port", "8080", "--no-proxy-headers", "--no-access-log"]
