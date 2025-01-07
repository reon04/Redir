FROM python:3.11-alpine
WORKDIR /app
COPY ./requirements.txt requirements.txt
RUN apk update && apk add --no-cache gcc musl-dev mariadb-dev mariadb-connector-c && \
  pip install --no-cache-dir --upgrade -r requirements.txt && \
  apk del gcc musl-dev
COPY . .
EXPOSE 80
CMD ["gunicorn", "--bind", "0.0.0.0:80", "app:app"]