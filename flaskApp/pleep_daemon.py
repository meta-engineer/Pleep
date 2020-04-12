
from flaskApp import db
from flaskApp import app
from .models import User, Thread, ThreadAssoc, Post, PostAssoc
from . import api
from .api.helpers import delete_upload
from passlib.hash import sha256_crypt
import os
import shutil
import time
import random
import datetime

def init_pleep_daemon():
    print(' * Making Pleep admin...')
    cryptedPassword = sha256_crypt.hash('takeapeepatmypleep')
    admin = User(name='Pleep', \
        password=cryptedPassword, \
        admin=True, \
        color="#000000", \
        timestamp=int(time.time()));

    pt = Thread(title="their Pleepline", \
        timestamp=int(time.time()), \
        creator=admin, \
        creator_id=admin.id, \
        write_access=False, \
        permission_list = admin.name)
    db.session.add(pt)
    db.session.commit()
    admin.profile_thread_id = pt.id

    db.session.add(admin)
    db.session.commit()
    # create first thread from daemon
    run_pleep_daemon()
    return

def run_pleep_daemon():
    print(" * running pleep daemon")

    # generate clout
    # subtract clout_static from clout
    # set new static clout (highest in profile_thread_id)
    # add static clout
    users = db.session.query(User).all()
    for u in users:
        bp = db.session.query(Post).filter_by(thread_id=u.profile_thread_id)
        bp = bp.order_by(Post.like_count.desc())
        bp = bp.first()
        if not bp:
            continue # just incase
        u.clout -= u.clout_static
        u.clout_static = bp.like_count
        u.clout += u.clout_static
        
    # close open threads past timestamp_close, award clout from thost threads
    # delete threads past timestamp_delete 
    threads = db.session.query(Thread)
    threads = threads.filter(Thread.title != 'their Pleepline').all()
    test_time = int(time.time())
    for t in threads:
        if t.closed and test_time > t.timestamp_delete:
            # kill (copied from /api/thread/delete to avoid session BS by logging in as admin)
            # naively search, delete all related data_filename... 
            for p in t.posts:
                if (p.data_filename):
                    delete_upload(p.data_filename)
            # delete q.posts(?) or query for posts with this thread_id and bulk delete
            db.session.query(Post).filter_by(thread_id=t.id).delete()
            # thread assocs should be nulled out?
            db.session.query(ThreadAssoc).filter_by(thread_id=t.id).delete()
            db.session.query(Thread).filter_by(id=t.id).delete()
            db.session.commit()
        elif (not t.closed) and test_time > t.timestamp_close:
            t.closed = True
            t.title = t.title + " (closed)"
            #award points
            finalists = 3
            best = db.session.query(Post).filter_by(thread_id=t.id)
            best = best.order_by(Post.like_count.desc())
            best = best.limit(finalists)
            best = best.all()
            for i in range(finalists):
                try:
                    # gain likes/placement as clout
                    best[i].author.clout += int( best[i].like_count / (i+1) )
                except Exception as err:
                    pass
            db.session.commit()
    
    #create monday thread?
    isItMonday = datetime.datetime.today()
    if isItMonday.weekday == 0:
        mt = Thread(title="Monday Thread")
        mt.timestamp = int(time.time())
        mt.timestamp_close = mt.timestamp + (1*24*60*60) # daily->only 1 active per day?
        mt.timestamp_delete = mt.timestamp +(2*24*60*60) # 1 additional day
        # get Pleep
        pleep = db.session.query(User).filter_by(name='Pleep').first()
        if (not pleep):
            return # no Pleep admin so just stop
        mt.creator_id = pleep.id
        mt.creator = pleep
        db.session.add(mt)
        db.session.commit()

        mp = Post()
        mp.text_content = "I love mondays"
        mp.author_id = pleep.id
        mp.timestamp = test_time
        mp.author = pleep
        mp.thread = mt
        mp.thread_id = mt.id
        shutil.copyfile(app.config['APP_DIRECTORY'] + "static/monday.png", app.config['APP_DIRECTORY'] + "uploads/monday.png")
        mp.data_filename = "monday.png"
        mp.data_type = "img"
        db.session.add(mp)
        db.session.commit()

    # create daily thread
    with open(app.config['APP_DIRECTORY'] + "static/verbs.txt") as verbs:
        verbList = verbs.read().splitlines()
        verb = random.choice(verbList)
    with open(app.config['APP_DIRECTORY'] + "static/nouns.txt") as nouns:
        nounList = nouns.read().splitlines()
        noun = random.choice(nounList)
    t = Thread(title=verb + " your " + noun)
    # add timestamp
    t.timestamp = test_time + 1
    t.timestamp_close = t.timestamp + (1*24*60*60) # daily->only 1 active per day?
    t.timestamp_delete = t.timestamp +(2*24*60*60) # 1 additional day
    # get Pleep
    pleep = db.session.query(User).filter_by(name='Pleep').first()
    if (not pleep):
        return # no Pleep admin so just stop
    t.creator_id = pleep.id
    t.creator = pleep
    pleep.lifetime_pleeps += 1
    db.session.add(t)
    db.session.commit()

    return