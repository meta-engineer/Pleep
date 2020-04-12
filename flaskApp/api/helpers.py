
from flask import json, session
from flaskApp import app
from flaskApp import db
import os

from flaskApp.models import User

# megirate to helpers file
#defines common return structure
def pleep_resp(data={}, status=400, error=''):
    return json.jsonify({'status':status, 'data':data, 'error':error})

def allowed_filename(filename):
    return '.' in filename and \
        filename.rsplit('.',1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def delete_upload(filename):
    path_to_file = app.config['APP_DIRECTORY'] + app.config['UPLOAD_DIRECTORY'] + filename
    if os.path.exists(path_to_file):
        os.remove(path_to_file)
        return True
    else:
        return False

def am_I_Admin():
    if session['logged_in']:
        return db.session.query(User).filter_by(name=session['username']).first().admin
    return False