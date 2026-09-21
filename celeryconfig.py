#config file for Celery

RABBITMQ_USER = 'guest'
RABBITMQ_PASS = 'guest'
RABBITMQ_IP = 'localhost'
RABBITMQ_Port = '5672'
#BROKER_URL = 'amqp://guest:guest@localhost:5672//'
BROKER_URL = 'amqp://' + RABBITMQ_USER + ":" + RABBITMQ_PASS + "@" + RABBITMQ_IP + ":" + RABBITMQ_Port + "//"
CELERY_RESULT_BACKEND = 'redis://localhost:6379/0'

CELERY_IMPORTS = ('common.jobs.tasks', 'common.merge_devices')

CELERY_RESULT_SERIALIZER = 'json'

CELERY_WORKER_DIRECT = True

CELERY_CREATE_MISSING_QUEUES = True