from celery import Celery
from setup import profile
import celeryconfig

app = Celery('celery')  #
#app.config_from_object('celeryconfig')
app.conf.broker_url = celeryconfig.BROKER_URL
app.conf.worker_direct = celeryconfig.CELERY_WORKER_DIRECT
app.conf.result_backend = celeryconfig.CELERY_RESULT_BACKEND
app.conf.imports = celeryconfig.CELERY_IMPORTS
app.conf.task_create_missing_queues = celeryconfig.CELERY_CREATE_MISSING_QUEUES
app.conf.result_serializer = celeryconfig.CELERY_RESULT_SERIALIZER

if __name__ == '__main__':
    #app.conf.task_default_exchange = 'celery'
    #app.conf.task_default_routing_key = 'celery'
    app.start()
