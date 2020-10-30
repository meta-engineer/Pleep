# Pleep
Pleep is a mock social media site that implements a full stack with Flask.
The backend has api endpoints which construct and manage an sql (sqlite) database through sqlalchemy
The frontend serves dynamic pages through Flask templating and HTML/CSS.

## Setup
 *While it is possible to set ENV and DEBUG in your config or code, 
    this is strongly discouraged. They can�t be read early by the flask command,
    and some systems or extensions may have already configured themselves based
    on a previous value*

*run from Pleep_Flask (this dir)*
set FLASK_APP=flaskApp,
set FLASK_ENV=development (or production),
set FLASK_RUN_PORT=XXXX

// flask install not recognised by flask, but is by python? (local dependandy error)
// likely solved by starting the project with virtualenv and installing locally

python -m flask run
or
flask run

## Database (SQLALCHEMY)
run python
from flaskApp import db         #Dababase object(?)
db.create_all()

from flaskApp import User
db.session.add(User(id=0, name='bill', password='bigBill'))
db.session.query(User).all()
db.session.query(User).filter_by(id=0).first().name
db.session.query(User).filter_by(id=0).delete()
db.session.commit()

## Notes on directory structuring
flask run must* be run from Pleep_Flask (*due to relative imports?)
so os operations run from Pleep_Flask
however
app is contained in flaskApp module (directory)
so flask operations run from Pleep_Flask/flaskApp

bandaid fix is to prepend all directories for os operations with 'Pleep_Flask'

## site partitions (blueprints)
/api -> get requests serve html, post requests are actual api
    This is kinda weird becuase GET and POST are not acting cannonically,
    all requests are POST but are differentiated by url.
    Except /download which allows both
    get requests should be admin only
    post requests should have approriate logged in restrictions

/    -> actual desktop version of pleep? at least homepage and thread pages?

filenames still override eachother even in seperate blueprints 
    -> seperation does not allow mirroring files

## TODO
deploy

proper login, flask-login
flask-mail
personal-profile (paging)
*READ_ONLY decorator/config? (security)
*post replying? -> post/create, post/delete
*caching?
