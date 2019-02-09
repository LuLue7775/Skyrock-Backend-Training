import os
BROKER_URL = os.environ.get('REDIS_URL', )
CELERY_RESULT_BACKEND = os.environ.get('REDIS_URL',)
CELERY_ACCEPT_CONTENT = ['application/json']
CELERY_TASK_SERIALIZER = 'json'
CELERY_RESULT_SERIALIZER = 'json'
CELERY_TIMEZONE = 'Africa/Nairobi'
