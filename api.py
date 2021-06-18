from fastapi import FastAPI, Depends, HTTPException, status, Form, Request
from fastapi.security import OAuth2AuthorizationCodeBearer, OAuth2PasswordRequestForm
import pickle
from fastapi.security.oauth2 import OAuth2PasswordBearer
import pymongo
from passlib.hash import bcrypt
from bson import json_util
import jwt
from bson.objectid import ObjectId
from faker import Faker
fake = Faker()
from datetime import datetime
import random
import os

# heroku url : https://salty-sea-10515.herokuapp.com/
# run local server : uvicorn api:app --reload
# API security example : https://www.youtube.com/watch?v=6hTRw_HK3Ts

app = FastAPI()
# oauth2_scheme = OAuth2PasswordBearer(tokenUrl='token')


# JWT_SECRET = os.environ.get('JWT_SECRET')

# client = pymongo.MongoClient(os.environ.get('JWT_SECRET'))
JWT_SECRET = 'myjwtsecret'

client = pymongo.MongoClient("mongodb+srv://vivien:serpython@cluster0.hozdq.mongodb.net/diary?retryWrites=true&w=majority")
db = client.diary


def verify_password(user, password):
    return bcrypt.verify(password, user['password'])

def get_current_user(token: str):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        user = db.users.find_one({'_id':payload.get('_id')})
    except:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='Invalid username or password'
        )
    return user




# @app.get("/emotions/{input}")
# def predict(input: str):
#     tfidf, model = pickle.load(open('model.bin', 'rb'))
#     proba = model.predict_proba(tfidf.transform([input])) #get emotion proba as a list of score without label [0.464,0.454,0.12,...]
#     res = dict(zip(model.classes_, proba[0])) # build dict with proba+label's names {'happy':0.12, 'sad':0.464,...}
#     res = dict(sorted(res.items(), key=lambda item: item[1], reverse=True)) # order this dict by score {'sad':0.464, 'happy':0.12, ...}
#     return {'input': input, 'emotions': res}

# @app.get("/users")
# def get_users():
#     db = get_db()
#     user['_id'] = str(user['_id'])
#     return {'users': json_util.dumps(db.users.find())}

@app.post("/users")
async def create_user(r: Request):
    form = await r.form()
    saved_user = dict(form)
    # saved_user['username'] = form["username"]
    saved_user['password'] = bcrypt.hash(form["password"])    
    saved_user['created_at'] = saved_user['updated_at'] = datetime.now()
    saved_user['_id'] = str(ObjectId())
    db.users.insert_one(saved_user)
    post_counts = random.randint(10,50)
    posts = list(db.kaggle_data.aggregate([ { '$sample': { 'size': post_counts } } ]))
    for post in posts:
        post['_id'] = str(ObjectId())
        post['created_at'] = post['updated_at'] = fake.date_time_between(start_date='-2y', end_date='now')
        post['user_id'] = saved_user['_id']
    db.posts.insert_many(posts)    
    return saved_user['_id']

@app.post("/posts")
async def create_post(r: Request):
    form = await r.form()
    post = dict(form)
    if get_current_user(post['token']):
        del post['token']  
        post['created_at'] = post['updated_at'] = datetime.now()
        post['emotion'] = predict(post['text'])['label']
        post['_id'] = str(ObjectId())
        db.posts.insert_one(post)
        return post['_id']


@app.get("/predict/{input}")
def predict(input: str):
    tfidf, model = pickle.load(open('model.bin', 'rb'))
    predictions = model.predict(tfidf.transform([input]))
    label = predictions[0]
    return {'text': input, 'label': label}


def is_author(token, post_id):
    user = get_current_user(token)
    post = db.posts.find_one(post_id)
    return user and post and user['_id'] == post['user_id']

@app.get("/posts/token/{token}")
async def get_posts(token):
    user = get_current_user(token)
    posts = db.posts.find({'user_id':user['_id']})  
    return list(posts)

@app.get("/posts/last/{token}")
async def get_posts(token):
    user = get_current_user(token)
    posts = db.posts.find({'user_id':user['_id']}).sort('created_at',-1).limit(1)
    return list(posts)     

@app.put("/posts/{post_id}")
async def update_post(post_id, r: Request):
    form = await r.form()
    data = dict(form)    
    if is_author(data['token'], post_id):
        del data['token']
        data['emotion'] = predict(data['text'])['label']
        data['updated_at'] = datetime.now()
        db.posts.update_one({'_id':post_id}, {'$set':data})
        return "post {} has been updated".format(post_id)


@app.delete("/posts/{post_id}")
async def update_post(post_id, r: Request):
    form = await r.form()
    data = dict(form)    
    if is_author(data['token'], post_id):
        db.posts.delete_one({'_id':post_id})
        return "post {} has been deleted".format(post_id)

@app.put("/users/{user_id}")
async def update_user(user_id, r: Request):
    form = await r.form()
    data = dict(form)
    db.users.update_one({'_id':user_id}, {'$set':data})
    
    # saved_user['username'] = form["username"]
    # saved_user['password'] = bcrypt.hash(form["password"])    
    # saved_user['created_at'] = saved_user['updated_at'] = datetime.now()
    # saved_user['_id'] = str(ObjectId())
    # db.users.insert_one(saved_user)
    return 'ok'   

"""
you need at least 2 endpoints, one for creating the token and one for auth
"""

async def authenticate_user(username: str, password: str):
    user = db.users.find_one({'username':username}, { 'username': 1, 'password': 1 })
    if not user or not verify_password(user, password):
        return False
    return user

@app.post('/token')
async def generate_token(r: Request):
    form = await r.form()

    user = await authenticate_user(form['username'], form['password'])
    if not user:
        return {'error': 'invalid credentials'}
    token = jwt.encode(user, JWT_SECRET)
    return {'access_token': token, 'token_type': 'bearer', 'user_id': user['_id']}

# @app.get('/')
# def index(token: str = Depends(oauth2_scheme)):
#     return {'the_token': token}
