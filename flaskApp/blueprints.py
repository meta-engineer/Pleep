from flask import Blueprint

# blueprint objects are in flaskApp so directories are relative to here
api = Blueprint('api', __name__, url_prefix='/api', template_folder='api/templates')
main = Blueprint('main', __name__, template_folder='main/templates')