from flaskApp import db
# use imports from db instead of sqlalchemy base

# ids generated by uuid4 (?)

follow_table = db.Table('follow_association', db.metadata,
    db.Column('followee_id', db.Integer, db.ForeignKey('users.id')),
    db.Column('follower_id', db.Integer, db.ForeignKey('users.id'))
)

like_table = db.Table('like_association', db.metadata,
    db.Column('user_id', db.Integer, db.ForeignKey('users.id')),
    db.Column('post_id', db.Integer, db.ForeignKey('posts.id'))
)

class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True, unique=True, autoincrement=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(100), unique=False, nullable=False)
    address = db.Column(db.String(50))
    color = db.Column(db.String(8), default='#000000')
    admin = db.Column(db.Boolean, nullable=False, default=False)
    clout = db.Column(db.Integer, default=0, nullable=False)
    #clout_static = db.Column(db.Integer, default=0, nullable=False)
    lifetime_pleeps = db.Column(db.Integer, default=0)
    timestamp = db.Column(db.Integer, nullable=False)

    image_filename = db.Column(db.String(100), default=None, nullable=True)
    image_type = db.Column(db.String(100), default=None, nullable=True)

    myPosts = db.relationship('Post', back_populates='author')
    myThreads = db.relationship('Thread', back_populates='creator')

    # profile_thread, named "their Pleepline", 
    # permission set to read true, write false (only them)
    # so thread queries must disclude these
    profile_thread_id = db.Column(db.Integer)

    # user's feed is active_threads they've followed and
    # active_posts which are created when a followee creates a post
    # array of "active" threads, notification of new replies?
    # One (user) to many (assocs)
    active_threads = db.relationship('ThreadAssoc', back_populates='user') # order_by=''
    active_posts = db.relationship('PostAssoc', back_populates='user')

    liked = db.relationship('Post', \
        secondary=like_table, \
        back_populates='likers')

    following = db.relationship('User', \
        secondary=follow_table, \
        primaryjoin = id==follow_table.c.follower_id, \
        secondaryjoin = id==follow_table.c.followee_id, \
        back_populates='followers')
    followers = db.relationship('User', \
        secondary=follow_table, \
        primaryjoin = id==follow_table.c.followee_id, \
        secondaryjoin = id==follow_table.c.follower_id, \
        back_populates='following')


    def jsonify(self):
        myThreadsIDs = []
        for t in self.myThreads:
            myThreadsIDs.append(t.id)
        myPostsIDs = []
        for p in self.myPosts:
            myPostsIDs.append(p.id)

        aThreadsIDs = []
        for t in self.active_threads:
            aThreadsIDs.append(t.thread_id)
        aPostsIDs = []
        for p in self.active_posts:
            aPostsIDs.append(p.post_id)

        followingIDs = []
        for f in self.following:
            followingIDs.append(f.id)

        likedIDs = []
        for l in self.liked:
            likedIDs.append(l.id)

        return {'id': self.id, 'name': self.name, 'admin': self.admin, \
            'address': self.address, 'color': self.color, 'clout': self.clout, \
            'image_filename': self.image_filename, \
            'myPosts': myPostsIDs, \
            'myThreads': myThreadsIDs, \
            'active_posts': aPostsIDs, \
            'active_threads': aThreadsIDs, \
            'followersCount': len(self.followers), \
            'followingIDs': followingIDs, \
            'profile_thread_id': self.profile_thread_id, \
            'lifetime_pleeps': self.lifetime_pleeps, \
            'likedIDs': likedIDs}

# track many to many threads to users
class ThreadAssoc(db.Model):
    __tablename__ = 'user_to_thread'
    __table_args__ = (
        db.PrimaryKeyConstraint('user_id', 'thread_id'),
    )

    user_id = db.Column(db.Integer, db.ForeignKey('users.id')) # nullable?
    user = db.relationship('User', back_populates='active_threads')

    # thread is unaware of assocs referencing it?
    # on thread deletion can call subroutine to delete thread Assocs (linear time)
    # should cascade thread deletions to assoc deletions
    # Many (assocs) to One (Thread)
    thread_id = db.Column(db.Integer, db.ForeignKey('pleep_threads.id'))
    thread = db.relationship('Thread')

    # metadata
    # by existing this assoc may already suggest metadata
    state = db.Column(db.Boolean, nullable=False, default=True)
    notifications = db.Column(db.Integer, nullable=False, default=0)

    def jsonify(self):
        return {'user_id': self.user_id, 'thread_id': self.thread_id, 'state': self.state}

class PostAssoc(db.Model):
    __tablename__ = 'user_to_post'
    __table_args__ = (
        db.PrimaryKeyConstraint('user_id', 'post_id'),
    )

    user_id = db.Column(db.Integer, db.ForeignKey('users.id')) # nullable?
    user = db.relationship('User', back_populates='active_posts')

    post_id = db.Column(db.Integer, db.ForeignKey('posts.id'))
    post = db.relationship('Post')

    # metadata
    # postAssocs are made by followees creating posts
    # postAssocs are removed by...? timeout?
    state = db.Column(db.Boolean, nullable=False, default=True)
    notifications = db.Column(db.Integer, nullable=False, default=0)

    def jsonify(self):
        return {'user_id': self.user_id, 'post_id': self.post_id, 'state': self.state}


'''
header object for collection of posts
permissions: 
    1/1 all read/all write, 
    1/0    all read/private list can write(or just author= list of 1)
    0/1 private list can read/all write
    0/0 private list can read/only author write
'''
class Thread(db.Model):
    __tablename__ = 'pleep_threads'

    id = db.Column(db.Integer, nullable=False, primary_key=True, unique=True, autoincrement=True)
    title = db.Column(db.String(100), nullable=False)
    categories = db.Column(db.String(1000))     # csv of 'hashtags'
    timestamp = db.Column(db.Integer, nullable=False)
    timestamp_close = db.Column(db.Integer)
    timestamp_delete = db.Column(db.Integer)
    closed = db.Column(db.Boolean, nullable=False, default=False)

    # back ref to display user info easier
    creator_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    creator = db.relationship("User", back_populates='myThreads')

    # One (Thread) to Many (Posts)
    posts = db.relationship('Post', back_populates='thread')

    total_likes = db.Column(db.Integer, nullable=False, default=0)

    # permissions work best with a friends list, otherwise private list
    # requires knowing all other user's names?
    # unless it queries for all usernames and filters in realtime for autocomplete
    read_access = db.Column(db.Boolean, nullable=False, default=True)
    write_access = db.Column(db.Boolean, nullable=False, default=True)
    permission_list = db.Column(db.String(1000), nullable=False, default='') # csv?

    # generate list of post ids
    def jsonify(self):
        postIDs = []
        for p in self.posts:
            postIDs.append(p.id)
        
        return {'id': self.id, \
            'title': self.title, \
            'categories': self.categories, \
            'timestamp': self.timestamp, \
            'timestamp_close': self.timestamp_close, \
            'timestamp_delete': self.timestamp_delete, \
            'closed': self.closed, \
            'creator': self.creator.name, \
            'creator_id': self.creator_id, \
            'postCount': len(self.posts), \
            'postIDs': postIDs, \
            'total_likes': self.total_likes}

#individual text/content posts made by users
class Post(db.Model):
    __tablename__ = 'posts'

    id = db.Column(db.Integer, nullable=False, primary_key=True, unique=True, autoincrement=True)
    text_content = db.Column(db.String(1000), nullable=False)
    data_filename = db.Column(db.String(100), default=None, nullable=True)
    # tag required to display
    data_type = db.Column(db.String(100), default=None, nullable=True)
    visibility = db.Column(db.Boolean, default=True, nullable=False)
    timestamp = db.Column(db.Integer, nullable=False) # time since Unix Epoch (can be seconds granularity)
    edit_timestamp = db.Column(db.Integer, default=None)

    thread_id = db.Column(db.Integer, db.ForeignKey('pleep_threads.id'))
    thread = db.relationship('Thread', back_populates='posts')
    # Many (Posts) to One (User)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    author = db.relationship('User', back_populates='myPosts')
    
    # many likes to many users
    likers = db.relationship('User', \
        secondary=like_table, \
        back_populates='liked')
    like_count = db.Column(db.Integer, nullable=False, default=0)

    def jsonify(self):
        likerIDs = []
        for l in self.likers:
            likerIDs.append(l.id)

        return {'id': self.id, \
            'thread_id': self.thread_id, \
            'thread_title': self.thread.title, \
            'author_id': self.author_id, \
            'author_name': self.author.name, \
            'author_color': self.author.color, \
            'timestamp': self.timestamp, \
            'edit_timestamp': self.edit_timestamp, \
            'thread_timestamp_close': self.thread.timestamp_close, \
            'text_content': self.text_content, \
            'data_filename': self.data_filename, \
            'data_type' : self.data_type, \
            'visibility': self.visibility, \
            'likes': self.like_count, \
            'likerIDs': likerIDs}