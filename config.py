# Sets Flask runtime features

class Config(object):
    FLASK_DEBUG = False
    TESTING = False
    SECRET_KEY = b'pleep'
    SQLALCHEMY_DATABASE_URI = 'sqlite:///pleepDB.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    MAX_CONTENT_LENGTH = 128 * 1024 * 1024  # 128 MB
    MAIL_ENABLED = False
    APP_DIRECTORY = 'flaskApp\\'
    UPLOAD_DIRECTORY = 'uploads\\'
    ALLOWED_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg', 'gif', 'mp3', 'mp4'}
    IMAGE_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
    FORBIDDEN_CHARACTERS = {',', '.', '\\', '/', ':', ';', '<', '>', ' '}
    READ_ONLY = False # Set true to disallow endpoints which modify server

class developmentConfig(Config):
    FLASK_DEBUG = True
    TESTING = True
    #FLASK_ENV = 'production' #set in env variables?
    EXPLAIN_TEMPLATE_LOADING = False

