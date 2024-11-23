import os
from flask import Flask, request, jsonify
from flask_cors import CORS
from supabase import create_client, Client
from werkzeug.security import generate_password_hash, check_password_hash
import uuid
import jwt
from datetime import datetime, timedelta
from dotenv import load_dotenv
import logging

def create_app():
    load_dotenv()
    app = Flask(__name__)
    
    # Configure logging
    logging.basicConfig(level=logging.DEBUG)
    app.logger.setLevel(logging.DEBUG)
    
    # Configure CORS
    CORS(app, 
         resources={
             r"/*": {
                 "origins": ["http://localhost:5000"],
                 "methods": ["GET", "POST", "OPTIONS"],
                 "allow_headers": ["Content-Type", "Authorization", "Accept"],
                 "expose_headers": ["Content-Type"],
                 "supports_credentials": True
             }
         })

    # Supabase Configuration
    SUPABASE_URL = os.environ.get('SUPABASE_URL')
    SUPABASE_KEY = os.environ.get('SUPABASE_KEY')
    supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

    # Secret key for JWT
    SECRET_KEY = os.environ.get('SECRET_KEY', 'your-secret-key')

    # Hardcoded Admin Credentials
    ADMIN_CREDENTIALS = {
        'email': 'admin@elimuglobal.com',
        'username': 'elimu_admin',
        'password': generate_password_hash('AdminElimG2024!')
    }

    @app.route('/signup', methods=['POST'])
    def signup():
        try:
            data = request.json
            app.logger.debug(f"Signup request data: {data}")

            # Extract user data
            email = data.get('email')
            password = data.get('password')
            name = data.get('name')
            role = data.get('role')

            # Check if user already exists
            existing_user = supabase.table('profiles').select('*').eq('email', email).execute()
            if existing_user.data:
                return jsonify({'message': 'User already exists'}), 400

            # Create user in Supabase Auth
            auth_user = supabase.auth.sign_up({
                'email': email,
                'password': password
            })

            # Prepare profile data
            profile_data = {
                'id': auth_user.user.id,
                'email': email,
                'name': name,
                'role': role,
                'password_hash': generate_password_hash(password),
                'is_approved': role != 'instructor'  # Auto-approve non-instructors
            }

            # Insert the profile into Supabase
            result = supabase.table('profiles').insert(profile_data).execute()
            
            if not result.data:
                return jsonify({'message': 'Registration failed'}), 500

            # Create instructor application if role is instructor
            if role == 'instructor':
                instructor_data = {
                    'profile_id': auth_user.user.id,
                    'status': 'pending'
                }
                supabase.table('instructor_applications').insert(instructor_data).execute()

            return jsonify({
                'message': 'Registration successful',
                'user': {
                    'id': auth_user.user.id,
                    'email': email,
                    'role': role,
                    'is_approved': role != 'instructor'
                }
            }), 201

        except Exception as e:
            app.logger.error(f"Signup error: {str(e)}")
            return jsonify({'message': f'Registration failed: {str(e)}'}), 500

    @app.route('/login/<user_type>', methods=['POST', 'OPTIONS'])
    def login(user_type):
        if request.method == 'OPTIONS':
            response = jsonify({'status': 'ok'})
            response.headers['Access-Control-Allow-Origin'] = 'http://localhost:5000'
            response.headers['Access-Control-Allow-Methods'] = 'POST, OPTIONS'
            response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, Accept'
            response.headers['Access-Control-Allow-Credentials'] = 'true'
            return response, 200

        try:
            data = request.json
            app.logger.debug(f'Login request data: {data}')
            
            email = data.get('email')
            password = data.get('password')

            if not all([email, password]):
                return jsonify({'message': 'Missing required fields'}), 400

            # Admin login
            if user_type == 'admin':
                if email == ADMIN_CREDENTIALS['email'] and check_password_hash(ADMIN_CREDENTIALS['password'], password):
                    token = jwt.encode({
                        'user_id': 'admin',
                        'email': email,
                        'role': 'admin',
                        'exp': datetime.utcnow() + timedelta(days=1)
                    }, SECRET_KEY, algorithm='HS256')
                    return jsonify({
                        'token': token,
                        'userType': 'admin',
                        'redirect': '/admin-dashboard',
                        'message': 'Login successful'
                    }), 200
                return jsonify({'message': 'Invalid admin credentials'}), 401

            # Regular user login
            user_query = supabase.table('profiles').select('*').eq('email', email).eq('role', user_type).execute()
            app.logger.debug(f'User query result: {user_query.data}')

            if not user_query.data:
                return jsonify({'message': 'User not found'}), 404

            user = user_query.data[0]

            if not check_password_hash(user['password_hash'], password):
                return jsonify({'message': 'Invalid credentials'}), 401

            # Check instructor approval status
            if user_type == 'instructor' and not user['is_approved']:
                return jsonify({'message': 'Your instructor account is pending approval'}), 403

            # Generate JWT token
            token = jwt.encode({
                'user_id': user['id'],
                'email': user['email'],
                'role': user['role'],
                'exp': datetime.utcnow() + timedelta(days=1)
            }, SECRET_KEY, algorithm='HS256')

            return jsonify({
                'token': token,
                'user': {
                    'id': user['id'],
                    'email': user['email'],
                    'role': user['role'],
                    'name': user['name'],
                    'is_approved': user['is_approved']
                },
                'message': 'Login successful'
            }), 200

        except Exception as e:
            app.logger.error(f'Login error: {str(e)}')
            return jsonify({'message': f'Login failed: {str(e)}'}), 500

    @app.route('/instructor-applications', methods=['GET'])
    def get_instructor_applications():
        try:
            # Get pending instructor applications
            applications = supabase.table('profiles') \
                .select('*') \
                .eq('role', 'instructor') \
                .eq('approval_status', 'pending') \
                .execute()

            return jsonify({
                'applications': applications.data
            }), 200

        except Exception as e:
            app.logger.error(f'Error fetching instructor applications: {str(e)}')
            return jsonify({'message': 'Failed to fetch instructor applications'}), 500

    @app.route('/approve-instructor/<instructor_id>', methods=['POST'])
    def approve_instructor(instructor_id):
        try:
            # Update instructor approval status
            result = supabase.table('profiles') \
                .update({'approval_status': 'approved'}) \
                .eq('id', instructor_id) \
                .execute()

            return jsonify({
                'message': 'Instructor approved successfully',
                'instructor': result.data[0]
            }), 200

        except Exception as e:
            app.logger.error(f'Error approving instructor: {str(e)}')
            return jsonify({'message': 'Failed to approve instructor'}), 500

    return app

if __name__ == '__main__':
    app = create_app()
    app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))
