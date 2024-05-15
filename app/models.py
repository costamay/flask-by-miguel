from app import db, login, app
from datetime import datetime, timezone
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from hashlib import md5
from sqlalchemy.orm import aliased
from time import time
import jwt

@login.user_loader
def load_user(id):
    return User.query.get(int(id))
    # return db.session.get(User, int(id))
followers = db.Table(
    'followers',
    db.metadata,
    db.Column('follower_id', db.Integer, db.ForeignKey('users.id'), primary_key=True),
    db.Column('followed_id', db.Integer, db.ForeignKey('users.id'), primary_key=True)
)

class User(UserMixin, db.Model):
    __tablename__ = "users"
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True)
    email = db.Column(db.String(120), unique=True)
    password = db.Column(db.String(256))
    bio = db.Column(db.String(140))
    last_seen = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    
    # Relationship mapping the user to related posts
    posts = db.relationship('Post', back_populates='user')
    
    # Many to many relationship mapping
    following = db.relationship(
        'User', 
        secondary=followers, 
        primaryjoin=(followers.c.follower_id == id),
        secondaryjoin=(followers.c.followed_id == id), 
        back_populates='followers')
    
    followers = db.relationship(
        'User', 
        secondary=followers, 
        primaryjoin=(followers.c.followed_id == id),
        secondaryjoin=(followers.c.follower_id == id),
        back_populates='following')
    
    def follow(self, user):
        if not self.is_following(user):
            self.following.append(user)
            
    def unfollow(self, user):
        if self.is_following(user):
            self.following.remove(user)
            
    def is_following(self, user):
        return any(follower.id == user.id for follower in self.following)
    # def is_following(self, user):
    #     query = User.query.where(User.id == user.id)
    #     return db.session.scalar(query) is not None
        
    def is_not_empty(lst):
        return bool(lst)
    
    def followers_count(self):
        return len(self.followers)
    
    def following_count(self):
        return len(self.following)
    
    def following_posts(self):
        Author = aliased(User)
        Follower = aliased(User)
        # Use query.outerjoin instead of separate join statements
        return (
            Post.query
            .join(Post.user.of_type(Author))
            .join(Author.followers.of_type(Follower), isouter=True)
            .where(db.or_(
                Follower.id == self.id,
                Author.id == self.id,
            ))
            .group_by(Post)
            .order_by(Post.created_at.desc())
        )
    
    def set_password(self, password):
        self.password = generate_password_hash(password)
        
    def check_password(self, password):
        return check_password_hash(self.password, password)
    
    def avatar(self, size):
        digest = md5(self.email.lower().encode('utf-8')).hexdigest()
        return f'https://www.gravatar.com/avatar/{digest}?d=identicon&s={size}'
    
    def get_reset_password_token(self, expires_in=600):
        return jwt.encode(
            {'reset_password': self.id,
             'exp': time() + expires_in
             },
            app.config['SECRET_KEY'],
            algorithm='HS256'
        )
        
    @staticmethod
    def verify_reset_password_token(token):
        try:
            id = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])['reset_password']
        except:
            return
        return db.session.get(User, id)
    
    def __repr__(self):
        return '<User {}>'.format(self.username)
    
class Post(db.Model):
    __tablename__ = "posts"
    
    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.String(140))
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    
    # Relationship mapping the post to related user
    user = db.relationship('User', back_populates='posts')
    
    def __repr__(self):
        return '<Post {}>'.format(self.body)
    
        