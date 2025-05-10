from sqlalchemy.orm import validates
from sqlalchemy.ext.hybrid import hybrid_property
from marshmallow import Schema, fields

from config import db, bcrypt

class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, unique=True, nullable=False)
    image_url = db.Column(db.String)
    bio = db.Column(db.String)
    _password_hash = db.Column(db.String)

    recipes = db.relationship('Recipe', backref='user')

    @hybrid_property
    def password_hash(self):
        raise AttributeError('Password hashes may not be viewed.')

    @password_hash.setter
    def password_hash(self, password):
        password_hash = bcrypt.generate_password_hash(
            password.encode('utf-8'))
        self._password_hash = password_hash.decode('utf-8')

    def authenticate(self, password):
        return bcrypt.check_password_hash(
            self._password_hash, password.encode('utf-8'))

    def __repr__(self):
        return f'<User {self.username}>'

class Recipe(db.Model):
    __tablename__ = 'recipes'
    __table_args__ = (
        db.CheckConstraint('length(instructions) >= 50'),
    )

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String, nullable=False)
    instructions = db.Column(db.String, nullable=False)
    minutes_to_complete = db.Column(db.Integer)

    user_id = db.Column(db.Integer(), db.ForeignKey('users.id'))

    def __repr__(self):
        return f'<Recipe {self.id}: {self.title}>'

class UserSchema(Schema):
    id = fields.Int()
    username = fields.String()
    image_url = fields.String()
    bio = fields.String()
    recipes = fields.List(fields.Nested(lambda: RecipeSchema(exclude=("user",))))

class RecipeSchema(Schema):
    id = fields.Int()
    title = fields.String()
    instructions = fields.String()
    minutes_to_complete = fields.Int()

    user = fields.Nested(UserSchema(exclude=("recipes",)))