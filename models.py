from sqlalchemy import Column, Integer, String
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash, generate_password_hash

from appkeygen import db

class ApiKeyModel(db.Model):
    __tablename__ = 'apikey'

    username = Column(String(120), unique=True, nullable=False) #modify as foreign key with user table user name
    app_id = Column(Integer, primary_key=True) #add unique constraint
    app_key = Column(String(255))

    def __init__(self, username, app_id, app_key):
        self.username = username
        self.app_id = app_id
        self.app_key = generate_password_hash(app_key, method='sha256')

    @classmethod
    def authenticate(cls, **kwargs):
        #username = kwargs.get('username')   # required?
        app_id = kwargs.get('Appid')
        app_key = kwargs.get('Appkey')

        if not app_key or not app_id:
            return None

        user = cls.query.filter_by(app_id=app_id).first()
        if not user or not check_password_hash(user.app_key, app_key):
            return None
        
        return user

    def json(self):
        return {
            'username': self.username,
            'app_id': self.app_id,
            'app_key': self.app_key
        }

    @classmethod
    def find_by_username(cls, username):
        return cls.query.filter_by(username=username).first()
    
    @classmethod
    def find_by_appid(cls, app_id):
        return cls.query.filter_by(app_id=app_id).first()

    def save_to_db(self):
        db.session.add(self)
        db.session.commit()

    def delete_from_db(self):
        db.session.delete(self)
        db.session.commit()

#db.create_all()

#Base.metadata.create_all(engine)

