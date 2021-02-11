from flask import Flask, request, jsonify
import bcrypt, jwt
from typing import Dict
from functools import wraps
from flask_sqlalchemy import SQLAlchemy
from datetime import date

app = Flask(__name__)

app.config['SECRET_KEY']='something secret'
app.config['SQLALCHEMY_DATABASE_URI']='sqlite:///app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS']=True
app.config['FLASK_ENV']='development'
app.config['FLASK_DEBUG']=1

db = SQLAlchemy(app)

class User(db.Model):
    id=db.Column(db.Integer, primary_key=True, index=True)
    name = db.Column(db.String(40), index=True)
    email=db.Column(db.String(40), index=True, unique=True)
    password=db.Column(db.String(108))
    activities=db.relationship('Activity', backref='users', lazy='dynamic')

class Activity(db.Model):
    id=db.Column(db.Integer, primary_key=True, index=True)
    name = db.Column(db.String(300), index=True)
    is_completed = db.Column(db.Boolean, default=False, index=True)
    date_created=db.Column(db.Date, default=date.today, index=True)
    date_ended=db.Column(db.Date, default=date.today, index=True)
    user_id=db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            token = request.headers['Authorization'].split(' ')[1]
        if not token: 
            return jsonify({
                'error': 'Unauthorized',
                'message': 'You did not provide a valid token'
                }), 401
        try:
            data=jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user=User.query.get_or_404(int(data['user_id']))
            if current_user is None:
                return jsonify({
                    'error': 'Unauthorized',
                    'message': 'Invalid token'
                }), 401
        except Exception as e:
            return jsonify({
                'error': 'Something went wrong',
                'message': str(e)
                }), 500

        return f(current_user, *args, **kwargs)

    return decorated

@app.route('/create-user', methods=['POST'])
def create_user():
    data: Dict[str, str] = request.get_json()
    if not 'name' in data or not 'email' in data or\
             not 'password' in data:
        return {
            'error': 'Invalid data',
            'message': 'Name, email and password must be given!'
        }, 400
    if not (4 < len(data['name']) < 40 and 
         6 < len(data['password']) < 20 and 
         10 < len(data['email']) < 40):
       return {
            'error': 'Invalid data',
            'message': 'Name must be between 4 and 20 characters,'
                       'email must be between 10 mand 40 characters and '
                       'password must be between 6 and 20 characters!'
        }, 400 
    user = {
        'name': data['name'],
        'email': data['email'],
        'password': bcrypt.hashpw(data['password'].encode('utf-8'), bcrypt.gensalt())
    }
    try:
        user = User(**user)
        db.session.add(user)
        db.session.commit()
    except:
        return {
            'error': 'Email has been chosen'
        }, 400
    return {
        'name': user.name,
        'email': user.email,
        'id': user.id
    }, 201

@app.route('/login', methods=['POST'])
def login():
    data: Dict[str, str] = request.get_json()
    if not 'email' in data or not 'password' in data:
        return {
            'error': 'Invalid data',
            'message': 'Name and password must be given!'
        }, 400
    user = User.query.filter_by(email=data['email']).first()
    if not user or not bcrypt.checkpw(data['password'].encode('utf-8'), user.password):
        return {
            'error': 'Invalid username or password'
        }, 401
    token = jwt.encode({'user_id': user.id}, key=app.config['SECRET_KEY'],  algorithm='HS256')
    return token

@app.route('/create-activity', methods=['POST'])
@token_required
def create_activity(current_user):
    data = request.get_json()
    if not 'name' in data:
        return {
            'error': 'Invalid data',
            'message': 'Name, must be given!'
        }, 400
    activity = Activity(
        name=data['name'], 
        user_id=current_user.id
    )
    activity.date_created = date(2021, 2, 5)
    db.session.add(activity)
    db.session.commit()
    return data, 201
 
@app.route('/view-activities/<int:id>')
@token_required
def view_activity(current_user, id):
    ac = Activity.query.get_or_404(id)
    return {
        'name': ac.name,
        'is completed': ac.is_completed,
        'date created': ac.date_created,
        'user': {
            'name': ac.users.name,
            'email': ac.users.email
        }
    }

@app.route('/view-activities')
@token_required
def view_activities(current_user):
    if request.args.get('today'):
        activity = Activity.query.filter(Activity.date_created == date.today()).all()
    elif request.args.get('week'):
        cur_week = date.today().isocalendar()
        last_week = date(cur_week[0], cur_week[1], 1)
        next_week = date(cur_week[0], cur_week[1], 7)
        last_week_date = date.today()
        activity = Activity.query.filter(Activity.date_created.between(last_week, next_week)).all()
    elif request.args.get('month'):
        today = date.today()
        last_month = date(today.year, today.month, 1)
        next_month = date(today.year, today.month, 28)
        activity = Activity.query.filter(Activity.date_created.between(last_month, next_month)).all()
    else:
        activity = Activity.query.all()
    
    activity = [{
        'name': ac.name,
        'is completed': ac.is_completed,
        'date created': ac.date_created,
        'user': {
            'name': ac.users.name,
            'email': ac.users.email
        }
    } for ac in activity]
    return jsonify(activity)

@app.route('/update-args/<int:id>', methods=['PUT'])
@token_required
def update_activity(current_user, id):
    data= request.get_json()
    activity = Activity.query.get_or_404(id)
    activity.is_completed = data.get('is completed') if data.get('is completed') else False
    db.session.commit()
    return {
        'messsage': 'Activity updated successfully'
    }, 201