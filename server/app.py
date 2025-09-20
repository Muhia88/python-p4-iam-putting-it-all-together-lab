#!/usr/bin/env python3

from flask import request, session, make_response, jsonify
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError

from config import app, db, api
# Make sure to import the User and Recipe models you created earlier
from models import User, Recipe

class Signup(Resource):
    def post(self):
        # Get data from the request
        data = request.get_json()
        
        # Create a new user instance
        new_user = User(
            username=data.get('username'),
            image_url=data.get('image_url'),
            bio=data.get('bio')
        )
        
        # Set the password using the password_hash setter
        new_user.password_hash = data.get('password')

        try:
            # Add and commit the new user to the database
            db.session.add(new_user)
            db.session.commit()

            # Set the user_id in the session
            session['user_id'] = new_user.id
            
            # Return the new user's data with a 201 status code
            return make_response(new_user.to_dict(rules=('-recipes',)), 201)

        except IntegrityError:
            # Handle cases where the username is not unique or other constraints fail
            return make_response({'errors': ['Validation errors']}, 422)

class CheckSession(Resource):
    def get(self):
        # Check if a user_id is in the session
        user_id = session.get('user_id')
        if user_id:
            # Find the user by their ID
            user = User.query.filter(User.id == user_id).first()
            if user:
                # Return the user's data if found
                return make_response(user.to_dict(rules=('-recipes',)), 200)
        
        # If no user is found or no session exists, return 401 Unauthorized
        return make_response({'error': 'Unauthorized'}, 401)

class Login(Resource):
    def post(self):
        # Get username from the request form
        username = request.get_json().get('username')
        password = request.get_json().get('password')

        # Find the user by username
        user = User.query.filter(User.username == username).first()

        # Check if the user exists and the password is correct
        if user and user.authenticate(password):
            # Set the user_id in the session
            session['user_id'] = user.id
            # Return the user's data
            return make_response(user.to_dict(rules=('-recipes',)), 200)
        
        # If authentication fails, return 401 Unauthorized
        return make_response({'error': 'Invalid credentials'}, 401)

class Logout(Resource):
    def delete(self):
        # Check if a user is logged in
        if session.get('user_id'):
            # Clear the user_id from the session
            session['user_id'] = None
            # Return a 204 No Content response
            return make_response('', 204)
        
        # If no user is logged in, return 401 Unauthorized
        return make_response({'error': 'Unauthorized'}, 401)

class RecipeIndex(Resource):
    def get(self):
        # Check if a user is logged in
        if session.get('user_id'):
            # Query all recipes from the database
            recipes = Recipe.query.all()
            # Serialize the list of recipes and return
            return make_response(
                [recipe.to_dict() for recipe in recipes],
                200
            )
        
        # If no user is logged in, return 401 Unauthorized
        return make_response({'error': 'Unauthorized'}, 401)
    
    def post(self):
        # Check if a user is logged in
        user_id = session.get('user_id')
        if not user_id:
            return make_response({'error': 'Unauthorized'}, 401)
        
        # Get data from the request
        data = request.get_json()
        
        try:
            # Create a new recipe instance, associating it with the logged-in user
            new_recipe = Recipe(
                title=data.get('title'),
                instructions=data.get('instructions'),
                minutes_to_complete=data.get('minutes_to_complete'),
                user_id=user_id
            )

            # Add and commit the new recipe
            db.session.add(new_recipe)
            db.session.commit()
            
            # Return the newly created recipe data with a 201 status code
            return make_response(new_recipe.to_dict(), 201)

        except (IntegrityError, ValueError) as e:
            # Handle validation errors
            db.session.rollback()
            return make_response({'errors': [str(e)]}, 422)


# Add the resources to the API
api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')


if __name__ == '__main__':
    app.run(port=5555, debug=True)