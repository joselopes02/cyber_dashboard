# celery_app.py
from celery import Celery
from .app import create_app  # Assuming you have a Flask app factory in app.py


def make_celery(app):
    celery = Celery(app.import_name,
                    broker=app.config['BROKER_URL'],
                    backend=app.config['RESULT_BACKEND'])
    celery.conf.update({
        'broker_url': app.config['BROKER_URL'],
        'result_backend': app.config['RESULT_BACKEND']
    })
    TaskBase = celery.Task

    class ContextTask(TaskBase):
        abstract = True

        def __call__(self, *args, **kwargs):
            with app.app_context():
                return TaskBase.__call__(self, *args, **kwargs)

    celery.Task = ContextTask
    return celery

flask_app = create_app()  # Create your Flask app instance
celery = make_celery(flask_app)

celery.autodiscover_tasks(['cyber_dashboard'])


# In celery_app.py (or a dedicated celeryconfig.py)
celery.conf.beat_schedule = {
    'update-statistics-every-10-minutes': {
        'task': 'cyber_dashboard.tasks.generate_static_statistics',
        'schedule': 600.0,  # 600 seconds = 10 minutes
    },
}
