# this file initializez a "Python Module". 
# Python will recognise the flaskApp directory as a "Module"

from flask import Flask
from flask_sqlalchemy import SQLAlchemy as alch
from apscheduler.schedulers.background import BackgroundScheduler
import atexit
import os
import time

#try changing to create_app factory
#def create_app(test_config=None):
app = Flask(__name__, static_url_path='/static', instance_relative_config=True)
	
#not all configs can be set from file, 
# must set FLAS_APP=flaskApp, FLASK_ENV=development, FLASK_RUN_PORT=XXXX, FLASK_DEBUG=True

#can config file be inside app? Kind annoying...
from config import developmentConfig
app.config.from_object('config.developmentConfig')

#create db in module and 
#from .db import db
#db.init_app(app)
db = alch(app)
from .models import User, Thread, ThreadAssoc, Post, PostAssoc
from . import api

"""
@app.cli.command('init-db')
def init_db_comand():
    #clean existing db file and rebuild
"""
try:
    db.session.query(User).all()
except Exception as err:
    db.create_all()
    from .pleep_daemon import init_pleep_daemon
    init_pleep_daemon()

if not os.path.exists(app.config['APP_DIRECTORY'] + app.config['UPLOAD_DIRECTORY']):
    os.makedirs(app.config['APP_DIRECTORY'] + app.config['UPLOAD_DIRECTORY'])

from . import main
# add endpoints as flask "blueprints"?
# allows global URL prefixing
from .blueprints import api, main
app.register_blueprint(api)
app.register_blueprint(main)

# flask stalls and 308's if there is no main route
@app.route('/')
def index():
    abort(404)

from .pleep_daemon import run_pleep_daemon
scheduler = BackgroundScheduler()
scheduler.start()
scheduler.add_job(func=run_pleep_daemon, trigger='cron', hour='0')
atexit.register(lambda: scheduler.shutdown())
