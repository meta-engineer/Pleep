# lists GET routes for application (web facade)
# POST/API endpoints are independant
# HTML pages here interact with them

from flask import Flask, render_template, flash, abort, redirect, url_for, \
    session, request, logging, send_from_directory, Blueprint

from flaskApp import app
from flaskApp import db
from passlib.hash import sha256_crypt

from flaskApp.decorators import is_logged_in

from flaskApp.blueprints import api

#error catch workaround
@api.route('/<path:path>')
def api_404(path):
    return render_template('api_404.html'), 404

@api.route('/')
def index():
    return render_template('api_index.html')# dynamic render based on logged in user

@api.route('/register', methods=['GET'])
def register_page():
    return render_template('register.html')

#check logged_in state and either log into new account or log out
@api.route('/login', methods=['GET'])
def login_page():
    #return error with render_template, error=...
    #{% if error} {% endif %}
    #{% for message in get_flashed_messages() %}
    #flash('You are logged out', 'success')
    return render_template('login.html')

@api.route('/logout', methods=['GET'])
def logout_page():
    return render_template('logout.html')

@api.route('/account/X', methods=['GET'])
def account_nav_page():
    return render_template('accountX.html')

#see own User entry in db
@api.route('/account', methods=['GET'])
def myAccount_page():
    if 'username' in session:
        return render_template('account.html', username=session['username'])
    else:
        return render_template('account.html', username='')


@api.route('/account/<username>', methods=['GET'])
def account_page(username):
    return render_template('account.html', username=username)

@api.route('/account/query', methods=['GET'])
def accounts_page():
    return render_template('accounts.html')

@api.route('/account/X/follow', methods=['GET'])
@is_logged_in
def followee_create_nav_page():
    return render_template("followee_create.html")

@api.route('/account/X/unfollow', methods=['GET'])
@is_logged_in
def followee_delete_nav_page():
    return render_template("followee_delete.html")

@api.route('/thread/X', methods=['GET'])
def thread_nav_page():
    return render_template('threadX.html')

@api.route('/thread/<int:tid>', methods=['GET'])
def thread_page(tid):
    return render_template('thread.html', tid=tid)

@api.route('/thread/query', methods=['GET'])
def threads_page():
    return render_template('threads.html')

@api.route('/thread/create', methods=['GET'])
@is_logged_in
def thread_create_page():
    return render_template('thread_create.html')

@api.route('/thread/X/delete', methods=['GET'])
@is_logged_in
def thread_delete_nav_page():
    return render_template('thread_delete.html')

@api.route('/thread/X/follow', methods=['GET'])
@is_logged_in
def thread_follow_nav_page():
    return render_template('thread_follow.html')

@api.route('/thread/X/unfollow', methods=['GET'])
@is_logged_in
def thread_unfollow_nav_page():
    return render_template('thread_unfollow.html')

@api.route('/post/<int:pid>', methods=['GET'])
def post_page(pid):
    return render_template('post.html', pid=pid)

@api.route('/post/X', methods=['GET'])
def post_nav_page():
    return render_template('postX.html')

@api.route('/post/query', methods=['GET'])
def posts_page():
    return render_template('posts.html')

@api.route('/post/create', methods=['GET'])
@is_logged_in
def post_create_page():
    return render_template('post_create.html')

@api.route('/post/X/delete', methods=['GET'])
@is_logged_in
def post_delete_nav_page():
    return render_template('post_delete.html')

@api.route('/post/X/like', methods=['GET'])
def post_like_nav_page():
    return render_template('post_like.html')

@api.route('/post/X/unlike', methods=['GET'])
def post_unlike_nav_page():
    return render_template('post_unlike.html')

@api.route('/upload', methods=['GET'])
def upload_page():
    return render_template('upload.html')
