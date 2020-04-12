from flask import Flask, render_template, flash, abort, redirect, url_for, \
    session, request, logging, send_from_directory, Blueprint, json

from flaskApp import app
from flaskApp import db
from passlib.hash import sha256_crypt

from flaskApp.decorators import is_logged_in

from flaskApp.blueprints import main

from flaskApp.api import api

# catch 403 errors?
@main.errorhandler(401)
def page_not_allowed(e):
    flash("You do not have permission to view that page", category="warning")
    return redirect(url_for('main.index'))

@app.errorhandler(404)
def page_not_found(e):
    return render_template('main_404.html'), 404
app.register_error_handler(404, page_not_found)

#error catch workaround
@main.route('/<path:path>')
def main_404(path):
    return render_template('main_404.html'), 404

@main.route('/')
def index():
    return render_template('home.html')

@main.route('/info')
def info_page():
    return render_template('public_info.html')

# thread dispatch
# paging with url parameters
@main.route('/thread/<int:tid>')
def thread_page(tid):
    thread_res = api.thread(tid).get_json()
    self_data = None
    if 'logged_in' in session.keys():
        self_res = api.self_account().get_json()
        if self_res['status'] == 200:
            self_data = self_res['data']
    if thread_res['status'] != 200:
        return main_404(0)
    else:
        return render_template('public_thread.html', thread_obj=thread_res['data'], self_obj=self_data, \
            order=request.args.get('order', default="popular", type=str), \
            page=request.args.get('page', default=0, type=int), \
            limit=request.args.get('limit', default=10, type=int), \
            feature=request.args.get('feature', type=int))

@main.route('/create_thread')
def create_thread_page():
    return render_template('public_create_thread.html')

# account dispatch. Should use flask-login object, but session for now
# paging with url parameters
@main.route('/account/<username>')
def account_page(username):
    account_res = api.account_by_name(username).get_json()
    self_data = None
    if 'logged_in' in session.keys():
        self_res = api.self_account().get_json()
        if self_res['status'] == 200:
            self_data = self_res['data']
    if account_res['status'] != 200:
        return main_404(0)
    else:
        return render_template('public_account.html', user_obj=account_res['data'], self_obj=self_data, \
            order=request.args.get('order', default="popular", type=str), \
            page=request.args.get('page', default=0, type=int), \
            limit=request.args.get('limit', default=10, type=int), \
            feature=request.args.get('feature', type=int))

# for settings? and private info
@main.route('/account')
@is_logged_in
def self_account_page():
    account_res = api.self_account().get_json()
    if account_res['status'] != 200:
        return main_404(0)
    else:
        return render_template('self_account.html', user_obj=account_res['data'])

@main.route('/register')
def register_page():
    return render_template('public_register.html')

# use URL parameters for
# paging with url parameters
@main.route('/search')
def search_page():
    # has to be one with js on page]
    return render_template('public_search.html', \
            substr=request.args.get('substr', default="", type=str), \
            type=request.args.get('type', default="post", type=str), \
            order=request.args.get('order', default="popular", type=str), \
            page=request.args.get('page', default=0, type=int), \
            limit=request.args.get('limit', default=10, type=int))

@main.route('/forgot_password')
def forgot_password_page():
    return render_template('forgot_password.html')