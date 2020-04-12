#lists POST routes for application

from flask import Flask, render_template, flash, redirect, url_for, session, request, logging, json, send_from_directory

from flaskApp import app
from flaskApp import db
from flaskApp.models import User, Thread, ThreadAssoc, Post, PostAssoc
from passlib.hash import sha256_crypt
from werkzeug.utils import secure_filename
import time
import os
import uuid
import random

from flaskApp.blueprints import api

from flaskApp.decorators import is_logged_in
# may need/want json extractor decorator for function definitions 
# instead of request.json

from .helpers import pleep_resp, allowed_filename, delete_upload, am_I_Admin

#all access
#sterilize input?
#email string validation
@api.route('/register', methods=['POST'])
def register():
    try:
        username = request.json['username']
        password = request.json['password']
        if (db.session.query(User).filter_by(name=username).first()):
            raise Exception("Username is already taken")
        for char in app.config['FORBIDDEN_CHARACTERS']:
            if char in username:
                raise Exception("Forbidden character in username: " + char)
        # password validation? (8+ chars...)
        if len(request.json['password']) < 8:
            raise Exception("Invalid password due to length < 8 characters")
        if password != request.json['password_confirm']:
            raise Exception("Password confirm does not match")
        for char in app.config['FORBIDDEN_CHARACTERS']:
            if char in password:
                raise Exception("Forbidden character in username: '" + char + "'")
        # sterilize input?
        cryptedPassword = sha256_crypt.hash(password)
        newU = User(name=username, password=cryptedPassword)
        if 'address' in request.json:
            newU.address = request.json['address']
        if 'color' in request.json:
            newU.color = request.json['color']
        newU.timestamp = int(time.time())

        if 'image_filename' in request.json and request.json['image_filename'] != '':
            dt = request.json['image_filename'].rsplit('.', 1)[1].lower()
            if not dt in app.config['IMAGE_EXTENSIONS']:
                raise Exception('File type not accepted, must be ' + ', '.join(app.config['IMAGE_EXTENSIONS']))
            newU.image_filename = request.json['image_filename']
            newU.image_type = dt
        else:
            #apply default image?
            # image paths used /api/downloads, these are in static...
            '''
            birdPath = app.config['APP_DIRECTORY'] + 'static\\gulls'
            fn = random.choice([
                x for x in os.listdir(birdPath)
                if os.path.isfile(os.path.join(birdPath, x))
            ])
            newU.image_filename = ... #fn
            newU.image_type = fn.rsplit('.', 1)[1].lower()
            '''

        #create profile thread (no timestamp_close/timestamp_delete)
        pt = Thread(title="their Pleepline", \
            timestamp=int(time.time()), \
            creator=newU, \
            creator_id=newU.id, \
            write_access=False, \
            permission_list = newU.name)
        db.session.add(pt)
        db.session.commit()
        newU.profile_thread_id = pt.id

        db.session.add(newU)
        db.session.commit()
        #pass get_flashed_messages() to the page and reload
        #flash('Register request completed', 'success')
        return pleep_resp(status=200)
    except Exception as err:
        #if err is thrown must delete possible upload
        if 'image_filename' in request.json and request.json['image_filename'] != '':
            delete_upload(request.json['image_filename'])

        return pleep_resp(status=400, error=str(err))

#all access
@api.route('/login', methods=['POST'])
def login():
    try:
        username = request.json['username']
        givenPassword = request.json['password']
    except Exception as err:
        return pleep_resp(status=400)

    try:
        matched_user = db.session.query(User).filter_by(name=username).first()
        storedPassword = matched_user.password
    except Exception as err:
        return pleep_resp(status=400)
    
    if sha256_crypt.verify(givenPassword, storedPassword):
        session['logged_in'] = True # test for session.logged_in in template
        session['username'] = username
        session['id'] = matched_user.id

        return pleep_resp(status=200)
    else:
        return pleep_resp(status=400)

@api.route('/logout', methods=['POST'])
@is_logged_in
def logout():
    session.clear()
    return pleep_resp(status=200)

@api.route('/account', methods=['POST'])
@is_logged_in
def self_account():
    try:
        accName = session['username']
    except Exception as err:
        # session has no value
        return pleep_resp(status=403, error=repr(err))
    else:
        currUser = db.session.query(User).filter_by(name=accName).first()
        if currUser:
            return pleep_resp(data=currUser.jsonify(), status=200)
        else:
            return pleep_resp(status=406, error='Logged in user not found')

@api.route('/account/<int:uid>', methods=['POST'])
def account_by_id(uid):
    try:
        u = db.session.query(User).filter_by(id=uid).first()
        if not u:
            raise Exception('User ID ' + str(uid) + ' does not exist')
        return pleep_resp(status=200, data=u.jsonify())
    except Exception as err:
        return pleep_resp(status=400, error=repr(err))

@api.route('/account/<username>', methods=['POST'])
def account_by_name(username):
    try:
        u = db.session.query(User).filter_by(name=username).first()
        if not u:
            raise Exception('Username ' + username + ' does not exist')
        return pleep_resp(status=200, data=u.jsonify())
    except Exception as err:
        return pleep_resp(status=400, error=repr(err))

# should be able to send query terms
# error check for request.json is empty?
# enforce default send is {} otherwise return 400
@api.route('/account/query', methods=['POST'])
def accounts():
    try:
        ary = []
        q = db.session.query(User)
        # query individual terms (id, name, admin)
        # include order(followers, clout), substr(name)
        if ('id' in request.json):
            q = q.filter_by(id= request.json['id'])
        if ('name' in request.json):
            q = q.filter_by(name= request.json['name'])
        if ('admin' in request.json):
            q = q.filter_by(admin= request.json['admin'])
        if ('substr' in request.json and request.json['substr'] != ''):
            q = q.filter(User.name.contains(request.json['substr']))
        # order then take top of size
        if ('order' in request.json):
            if (request.json['order'] == 'timestamp'):
                q = q.order_by(User.timestamp.desc())
            elif (request.json['order']=='clout'):
                q = q.order_by(User.clout.desc())
        # this is untested :(
        if ('limit' in request.json):
            q = q.limit(int(request.json['limit']))

        q = q.all()
        for r in q:
            ary.append(r.jsonify())
        return pleep_resp(status=200, data=ary)
    except Exception as err:
        return pleep_resp(status=400, error=repr(err))

# add followers
@api.route('/account/<int:uid>/follow', methods=['POST'])
@is_logged_in
def followee_create(uid):
    try:
        if uid == session['id']:
            raise Exception("User IDs match, cannot follow yourself")
        # add session['username'] as follower of requests.json.id
        will_smith = db.session.query(User).filter_by(id=uid).first()
        if not will_smith:
            raise Exception('Followee ID ' + str(uid) + ' does not exist')
        to_follow = db.session.query(User).filter_by(id=session['id']).first()
        if not will_smith in to_follow.following:
            to_follow.following.append(will_smith)
            db.session.commit()
            return pleep_resp(status=200, data='Follow create complete')
        return pleep_resp(status=200, data='Follow already exists')
    except Exception as err:
        return pleep_resp(status=404, error=repr(err))
    
# remove followers
@api.route('/account/<int:uid>/unfollow', methods=['POST'])
@is_logged_in
def followee_delete(uid):
    try:
        # remove session['username'] as follower of requests.json.id
        will_smith = db.session.query(User).filter_by(id=uid).first()
        if not will_smith:
            raise Exception('Followee ID ' + str(uid) + ' does not exist')
        to_follow = db.session.query(User).filter_by(id=session['id']).first()
        if to_follow in will_smith.followers:
            will_smith.followers.remove(to_follow)
            db.session.commit()
            return pleep_resp(status=200, data='Follow delete complete')
        return pleep_resp(status=200, data='Follow does not exist')
    except Exception as err:
        return pleep_resp(status=404, error=repr(err))

@api.route('/thread/<int:tid>', methods=['POST'])
def thread(tid):
    try:
        t = db.session.query(Thread).filter_by(id=tid).first()
        if (not t):
            raise Exception("Thread ID " + str(tid) + " does not exist")
        return pleep_resp(data=t.jsonify(), status=200)
    except Exception as err:
        return pleep_resp(status=404, error=repr(err))

# must be admin or thread owner?
@api.route('/thread/<int:tid>/modify', methods=['POST'])
@is_logged_in
def thread_modify(tid):
    try:
        # naive implementation, allow each request to modify any members?
        # no, uneasy about undefined behaviour
        # strict implementation, search request for specific members to modify
        t = db.session.query(Thread).filter_by(id=tid).first()
        if (not t):
            raise Exception("Thread ID " + str(tid) + " does not exist")
        isAdmin = am_I_Admin()
        if (not isAdmin and session['username'] != t.posts[0].author.name):
            return pleep_resp(status=403, error="Access denied")

        if 'title' in request.json:
            t.title = request.json['title']
        if 'categories' in request.json:
            t.categories = request.json['categories']
        db.session.commit()
        return pleep_resp(status=200, data=t.jsonify())
    except Exception as err:
        return pleep_resp(status=400, error=repr(err))

@api.route('/thread/query', methods=['POST'])
def threads():
    try:
        ary = []
        q = db.session.query(Thread)
        # query individual terms (id, title, creator_id)
        # include order(postCount, timestamp), limit, substr(title)
        if ('id' in request.json):
            q = q.filter_by(id= request.json['id'])
        if ('title' in request.json):
            q = q.filter_by(title= request.json['title'])
        if ('creator_id' in request.json):
            q = q.filter_by(creator_id= request.json['creator_id'])
        if ('creator_name' in request.json):
            q = q.filter(Thread.creator.has(name=request.json['creator_name']))
        if ('substr' in request.json and request.json['substr'] != ''):
            q = q.filter(Thread.title.contains(request.json['substr']))
        # order then take top of size
        if ('order' in request.json):
            if (request.json['order'] == 'timestamp'):
                q = q.order_by(Thread.timestamp.desc())
            elif (request.json['order']=='total_likes'):
                q = q.order_by(Thread.total_likes.desc())

        # filter out 'their Pleepline' threads?
        q = q.filter(Thread.title != 'their Pleepline')

        if ('limit' in request.json):
            q = q.limit(int(request.json['limit']))
        q = q.all()
        for r in q:
            ary.append(r.jsonify())
        # query for all threads build
        return pleep_resp(status=200, data=ary)
    except Exception as err:
        return pleep_resp(status=400, error=repr(err))

# client must use thread id to make init post and (optionally) add to user active
@api.route('/thread/create', methods=['POST'])
@is_logged_in
def thread_create():
    # accept title, category info
    # use session info to complete
    try:
        t = Thread(**(request.json))
        # add timestamp
        t.timestamp = int(time.time())
        t.timestamp_close = t.timestamp + (3*24*60*60) # 3 day default for now?
        t.timestamp_delete = t.timestamp +(6*24*60*60) # another week?
        
        t.creator_id = session['id']
        t.creator = db.session.query(User).filter_by(id=t.creator_id).first()
        db.session.add(t)
        db.session.commit()
        #flash(t.jsonify())
        return pleep_resp(status=200, data=t.jsonify())
    except Exception as err:
        return pleep_resp(status=400, error=repr(err))

# This should likely be donw ith a recursive call to a delete_post function
# bulk delete may be more efficient but upkeep might suffer in future
@api.route('/thread/<int:tid>/delete', methods=['POST'])
@is_logged_in
def thread_delete(tid):
    #accepts id
    try:
        isAdmin = am_I_Admin()
        t = db.session.query(Thread).filter_by(id=tid)
        if (not t.first()):
            raise Exception("Thread ID " + str(tid) + " does not exist")
        if (not isAdmin and session['username'] != t.first().creator.name):
            return pleep_resp(status=403, error="Access denied")

        # naively search, delete all related data_filename... 
        for p in t.first().posts:
            if (p.data_filename):
                delete_upload(p.data_filename)
        # delete q.posts(?) or query for posts with this thread_id and bulk delete
        db.session.query(Post).filter_by(thread_id=tid).delete()
        t.delete()
        # thread assocs should be nulled out?
        db.session.query(ThreadAssoc).filter_by(thread_id=tid).delete()

        db.session.commit()
        return pleep_resp(status=200)
    except Exception as err:
        return pleep_resp(status=400, error=repr(err))

@api.route('/thread/<int:tid>/follow', methods=['POST'])
@is_logged_in
def thread_follow(tid):
    try:
        newState = True # what does this mean, is it meaningful to set otherwise on create?
        thread = db.session.query(Thread).filter_by(id=tid).first()
        if (not thread):
            raise Exception("Thread ID " + str(tid) + " does not exist")
        follower = db.session.query(User).filter_by(id=session['id']).first()

        # does ta already exist
        ta = db.session.query(ThreadAssoc).filter_by(user_id=session['id'], thread_id=tid).first()
        if ta:
            ta.state = newState
            db.session.commit()
            return pleep_resp(status=200, data=ta.jsonify())
        else:
            t = ThreadAssoc(user_id=session['id'], thread_id=tid, state=newState)
            t.thread = thread
            t.user = follower
            db.session.add(t)
            db.session.commit()
            return pleep_resp(status=200, data=t.jsonify())
    except Exception as err:
        return pleep_resp(status=400, error=repr(err))

@api.route('/thread/<int:tid>/unfollow', methods=['POST'])
@is_logged_in
def thread_unfollow(tid):
    try:
        thread = db.session.query(Thread).filter_by(id=tid).first()
        if (not thread):
            raise Exception("Thread ID " + str(tid) + " does not exist")
        follower = db.session.query(User).filter_by(id=session['id']).first()
        
        q = db.session.query(ThreadAssoc).filter_by(user_id=session['id'], thread_id=tid).first()
        if q:
            db.session.delete(q)
            db.session.commit()
            return pleep_resp(status=200, data="TA " + session['username'] + " -> " + str(tid) + " deleted")
        return pleep_resp(status=200, data="Already unfollowing")
    except Exception as err:
        return pleep_resp(status=400, error=repr(err))

@api.route('/post/<int:pid>', methods=['POST'])
def post(pid):
    try:
        p = db.session.query(Post).filter_by(id=pid).first()
        if (not p):
            raise Exception("Post ID " + str(pid) + " does not exist")
        return pleep_resp(data=p.jsonify(), status=200)
    except Exception as err:
        return pleep_resp(status=404, error=repr(err))

@api.route('/post/<int:pid>/modify', methods=['POST'])
@is_logged_in
def post_modify(pid):
    try:
        # naive implementation, allow each request to modify any members?
        # no, uneasy about undefined behaviour
        # strict implementation, search request for specific members to modify
        p = db.session.query(Post).filter_by(id=pid).first()
        if (not p):
            raise Exception("Post ID " + str(pid) + " does not exist")
        isAdmin = am_I_Admin()
        if (not isAdmin and session['username'] != p.author.name):
            return pleep_resp(status=403, error="Access denied")

        # post changing threads is not really useful?
        if ('text_content' in request.json):
            p.text_content = request.json['text_content']
            p.edit_timestamp = int(time.time())
        if ('data_filename' in request.json):
            p.data_filename = request.json['data_filename']
            p.data_type = request.json['data_filename'].rsplit(',', 1)[1].lower()
            p.edit_timestamp = int(time.time())
        # users can hide posts but not reshow (used for blank thread posts)
        if ('visibility' in request.json and (isAdmin or p.visibility == True)):
            p.visibility = request.json['visibility']
        db.session.commit()
        return pleep_resp(status=200, data=p.jsonify())
    except Exception as err:
        return pleep_resp(status=400, error=repr(err))

@api.route('/post/query', methods=['POST'])
def posts():
    try:
        # query individual terms (id, data_type, thread_id, author_id)
        # include order(timestamp, likes), limit, substr(text_content)
        ary = []
        q = db.session.query(Post)
        if ('id' in request.json):
            q = q.filter_by(id= request.json['id'])
        if ('data_type' in request.json):
            q = q.filter_by(data_type= request.json['data_type'])
        if ('thread_id' in request.json):
            q = q.filter_by(thread_id= request.json['thread_id'])
        if ('author_id' in request.json):
            q = q.filter_by(author_id= request.json['author_id'])
        if ('substr' in request.json and request.json['substr'] != ''):
            q = q.filter(Post.text_content.contains(request.json['substr']))
        # order then take top of size
        if ('order' in request.json):
            if (request.json['order'] == 'timestamp'):
                q = q.order_by(Post.timestamp.desc())
            elif (request.json['order']=='likes'):
                q = q.order_by(Post.like_count.desc())
        # always filter by visibility
        q = q.filter_by(visibility=True)
        # this is untested :(
        if ('limit' in request.json):
            q = q.limit(int(request.json['limit']))
        q = q.all()
        for r in q:
            ary.append(r.jsonify())
        return pleep_resp(status=200, data=ary)
    except Exception as err:
        return pleep_resp(status=400, error=repr(err))

# filter what arguments can be set and what are set by system
@api.route('/post/create', methods=['POST'])
@is_logged_in
def post_create():
    try:
        p = Post(**(request.json))
        myself = db.session.query(User).filter_by(name=session['username']).first()
        # use session info to complete author
        p.author = myself
        p.author_id = myself.id
        # add timestamp
        p.timestamp = int(time.time())
        # add thread from id
        p.thread = db.session.query(Thread).filter_by(id=p.thread_id).first()
        if not p.thread:
            raise Exception("Parent thread ID: " + p.thread_id + " does not exist")
        if (int(time.time()) > p.thread.timestamp_close):
            raise Exception("Thread ID: " + p.thread_id + " is closed")
 
        # add data type from data_filename?
        # let frontend add this incase weird filetypes come up
        if 'data_filename' in request.json:
            ext = request.json['data_filename'].rsplit('.', 1)[1].lower()
            if ext in {'mp3'}:
                p.data_type = "audio"
            elif ext in {'mp4'}:
                p.data_type = "video"
            elif ext in app.config['IMAGE_EXTENSIONS']:
                p.data_type = "img"
            else:
                p.data_type = ""

        db.session.add(p)
        
        # notify followers of post
        # no need to check duplicate, cannot exist already
        for f in myself.followers:
            pa = PostAssoc(user_id= f.id, post_id=p.id , state=True)
            pa.post = p
            pa.user = f
            db.session.add(pa)

        myself.lifetime_pleeps += 1

        db.session.commit()
        return pleep_resp(status=200, data=p.jsonify())
    except Exception as err:
        return pleep_resp(status=400, error=repr(err))

# can users delete? or just void
# how does delete operate with reply structures?
# also delete attached data file?
@api.route('/post/<int:pid>/delete', methods=['POST'])
@is_logged_in
def post_delete(pid):
    # accepts id
    # requires admin login or owner of post?
    # if ilya reply structure, only removes post body? -> use modify
    try:
        q = db.session.query(Post).filter_by(id=pid)
        if (not q.first()):
            raise Exception("Post ID " + str(pid) + " does not exist")

        if (not (q.first().data_filename == None)):
            if not delete_upload(q.first().data_filename):
                raise Exception('Failed to delete attached file, aborting post delete')
        q.delete()
        # post assocs should be nulled out?
        db.session.query(PostAssoc).filter_by(post_id=pid).delete()

        db.session.commit()
        return pleep_resp(status=200)
    except Exception as err:
        return pleep_resp(status=400, error=repr(err))

@api.route('/post/<int:pid>/like', methods=['POST'])
@is_logged_in
def post_like(pid):
    try:
        liker = db.session.query(User).filter_by(id=session['id']).first()
        post = db.session.query(Post).filter_by(id=pid).first()
        if (not post):
            raise Exception("Post ID " + str(pid) + " does not exist")
        if not post in liker.liked:
            liker.liked.append(post)
            post.like_count += 1
            post.thread.total_likes += 1
            db.session.commit()
            return pleep_resp(status=200, data="Post ID " + str(pid) + " liked")
        return pleep_resp(status=200, data="Post ID " + str(pid) + " is already liked")
    except Exception as err:
        return pleep_resp(status=400, error=repr(err))

@api.route('/post/<int:pid>/unlike', methods=['POST'])
@is_logged_in
def post_unlike(pid):
    try:
        liker = db.session.query(User).filter_by(id=session['id']).first()
        post = db.session.query(Post).filter_by(id=pid).first()
        if (not post):
            raise Exception("Post ID " + str(pid) + " does not exist")
        if post in liker.liked:
            liker.liked.remove(post)
            post.like_count -= 1
            post.thread.total_likes -= 1
            db.session.commit()
            return pleep_resp(status=200, data="Post ID " + str(pid) + " unliked")
        return pleep_resp(status=200, data="Post ID " + str(pid) + " is already unliked")
    except Exception as err:
        return pleep_resp(status=400, error=repr(err))


@api.route('/upload/<filename>', methods=['POST'])
def upload(filename):
    try:
        if "/" in filename:
            pleep_resp(status=400, error='no subdirectories allowed')

        if filename not in request.files:
            raise Exception("File not found in request")
        
        upfile = request.files[filename]

        if request.files[filename].filename == '':
            raise Exception("Empty file")

        # check extension
        if not allowed_filename(filename):
            raise Exception("Accepted filetypes: " + app.config['ALLOWED_EXTENSIONS'].join(", "))
        # generate new unique filename
        unique_filename = str(uuid.uuid4()) + '.' + filename.rsplit('.',1)[1].lower()

        # os has cwd in PLEEP_FLASK
        #with open(os.path.join(app.config['UPLOAD_DIRECTORY'], unique_filename), "wb") as fp:
        #    fp.write(upfile.read())
        upfile.save(os.path.join(app.config['APP_DIRECTORY'] + app.config['UPLOAD_DIRECTORY'], unique_filename))

        # return unique username to be attached to post
        return pleep_resp(status=201, data=unique_filename)
    except Exception as err:
        return pleep_resp(status=400, error=str(err))

     
@api.route('/download/<path:filename>', methods=['POST', 'GET'])
def download(filename):
    # flask has cwd in \flaskapp\ so send_from_directory wants uploads/file.ext
    return send_from_directory(app.config['UPLOAD_DIRECTORY'], filename)
