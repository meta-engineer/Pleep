from flask import Flask, flash, redirect, url_for, session, request, logging, abort
from functools import wraps

#checks flasks session for preset attribute
# should redirect back to page diverted from after login
def is_logged_in(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            #flash('Unauthorized', 'danger')
            #return redirect(url_for('login'))
            return abort(401)
    return wrapper
