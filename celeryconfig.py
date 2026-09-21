#config file for Celery
import os

# Matches the TE_RABBITMQ_* names enterprise_conf.py already uses - keeping the two in sync
# means a Docker Compose service name (e.g. TE_RABBITMQ_HOST=rabbitmq) reaches both the web app
# and Celery without any extra wiring.
RABBITMQ_USER = os.environ.get("TE_RABBITMQ_USER", "guest")
RABBITMQ_PASS = os.environ.get("TE_RABBITMQ_PASS", "guest")
RABBITMQ_IP = os.environ.get("TE_RABBITMQ_HOST", "localhost")
RABBITMQ_Port = os.environ.get("TE_RABBITMQ_PORT", "5672")
BROKER_URL = 'amqp://' + RABBITMQ_USER + ":" + RABBITMQ_PASS + "@" + RABBITMQ_IP + ":" + RABBITMQ_Port + "//"

REDIS_HOST = os.environ.get("TE_REDIS_HOST", "localhost")
REDIS_PORT = os.environ.get("TE_REDIS_PORT", "6379")
REDIS_DB = os.environ.get("TE_REDIS_DB", "0")
CELERY_RESULT_BACKEND = 'redis://' + REDIS_HOST + ':' + REDIS_PORT + '/' + REDIS_DB

CELERY_IMPORTS = ('common.jobs.tasks', 'common.merge_devices')

CELERY_RESULT_SERIALIZER = 'json'

CELERY_WORKER_DIRECT = True

CELERY_CREATE_MISSING_QUEUES = True
