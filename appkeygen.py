from flask import Flask, request, jsonify
from flask_restful import Resource, Api
from werkzeug.security import generate_password_hash
import os
import random, string
from binascii import hexlify
from flask_sqlalchemy import SQLAlchemy
SQLALCHEMY_DATABASE_URI = 'sqlite:///data.db'
app = Flask(__name__)
api = Api(app)
app.config["SQLALCHEMY_DATABASE_URI"] = SQLALCHEMY_DATABASE_URI
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)


class ApiKey(Resource):
    """
    This resource will handle create, update, deletion of AppId, AppKey
    param: username
    ret_val: Json with AppId, AppKey or Message and return code
    """
    def get(self, username):    #get required?
        app_data = ApiKeyModel.find_by_username(username)
        if app_data:
            return app_data.json()
        return {'Message': 'User not found. Please create new one'}, 404

    
    def post(self, username):
        app_data = ApiKeyModel.find_by_username(username)
        if app_data:
            return { 'Message': "App_Key is already available for this user: {}. If lost user's key, please create new one".format(username) }, 400
        app_key = hexlify(os.urandom(21))
        app_id = ApiKey.create_app_id()
        data = {'username': username, 'app_id': app_id, 'app_key': app_key.decode('utf-8')}
        app_data = ApiKeyModel(**data)
        try:
            app_data.save_to_db()
        except Exception as e:
            return {"Message" : "Error during save data",  "Error details:": "{}".format(e)}, 500  #error message should be written in logger file
        
        return data, 201 
    
    
    @classmethod
    def create_unique_id(cls):
        return ''.join(random.choices(string.digits, k=8))

    @classmethod
    def create_app_id(cls):
        id = ApiKey.create_unique_id()
        unique = False
        while not unique:
            if not ApiKeyModel.find_by_appid(id):
                unique = True
            else:
                id = ApiKey.create_unique_id()
        return int(id)
    

    def delete(self, username):   #add logic to check admin previlege, admin only can delete
        app_data = ApiKeyModel.find_by_username(username)
        if app_data:
            app_data.delete_from_db()
            return {"Message": "Key deleted for the user {}".format(username)}
        return {"Message": "User not found"}, 404

    def put(self, username):
        app_data = ApiKeyModel.find_by_username(username)
        if app_data:  
            new_key = hexlify(os.urandom(21))
            try:
                app_data.app_key = generate_password_hash(new_key.decode('utf-8'),  method='sha256')
                app_data.save_to_db()
                return {"New Key": new_key.decode('utf-8')}
            except:
                return {"Message": "Error in update db"}
        return {"Message": "User not found to update App_Key."}

api.add_resource(ApiKey, '/apikey/<username>')


#test
@app.route('/testapi', methods=['GET'])
def test_api():
    """
    function to test above api resource.
    """
    header_data = dict(request.headers)
    if not ApiKeyModel.authenticate(**header_data):
        return {"Message": "App_key Authentication failed"}, 401
    return{"Message": "Auth Success"}


if __name__ == "__main__":
    from models import ApiKeyModel
    app.run(port=5000)
