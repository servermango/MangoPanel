FROM python:3.11-slim

WORKDIR /app
COPY . .

ENV MP_HOST=0.0.0.0
ENV MP_PORT=8000
EXPOSE 8000

CMD ["python", "-m", "mangopanel.app"]

