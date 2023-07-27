FROM python:3.11-slim
WORKDIR /app
COPY . .
RUN pip install -r requirements-dev.txt
RUN pip install gunicorn
CMD gunicorn epasswd.wsgi:application --bind 0.0.0.0:80
