import os
from flask import Flask, request, jsonify, redirect
from flask_cors import CORS
from supabase import create_client, Client
from werkzeug.security import generate_password_hash, check_password_hash
import uuid
import jwt
from datetime import datetime, timedelta
from dotenv import load_dotenv

def create_app():
    load_dotenv()
    app = Flask(__name__)
    
    # Configure logging
    import logging
    logging.basicConfig(level=logging.DEBUG)
    app.logger.setLevel(logging.DEBUG)
    
    # Print all registered routes on startup
    def log_routes():
        app.logger.debug("Registered routes:")
        for rule in app.url_map.iter_rules():
            app.logger.debug(f"{rule.endpoint}: {rule.methods} - {rule}")
    
    # Configure CORS with more permissive settings
    CORS(app, 
         resources={
             r"/*": {
                 "origins": ["http://localhost:5000"],
                 "methods": ["GET", "POST", "OPTIONS"],
                 "allow_headers": ["Content-Type", "Authorization", "Accept"],
                 "expose_headers": ["Content-Type"],
                 "supports_credentials": True,
                 "send_wildcard": False,
                 "max_age": 86400
             }
         })

    # Ensure the app can handle JSON requests
    app.config['CORS_HEADERS'] = 'Content-Type'

    # Supabase Configuration
    SUPABASE_URL = os.environ.get('SUPABASE_URL')
    SUPABASE_KEY = os.environ.get('SUPABASE_KEY')
    supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

    # Secret key for JWT
    SECRET_KEY = os.environ.get('SECRET_KEY', 'your_super_secret_key')

    # Hardcoded Admin Credentials
    ADMIN_CREDENTIALS = {
        'email': 'admin@elimuglobal.com',
        'username': 'elimu_admin',
        'password': generate_password_hash('AdminElimG2024!')
    }

    def setup_database():
        """Creates the necessary tables if they don't exist"""
        try:
            # Instead of checking if table exists, we'll use try-except
            # Create users table using Supabase's SQL editor or dashboard
            print("Please ensure the users table is created in Supabase dashboard")
            return True
        except Exception as e:
            print(f"Error setting up database: {str(e)}")
            return False

    # Call setup_database during app initialization
    with app.app_context():
        setup_database()

    @app.route('/', methods=['GET'])
    def home():
        return jsonify({'message': 'Welcome to Elimu Global API'}), 200

    @app.route('/signup', methods=['POST'])
    def signup():
        data = request.json
        role = data.get('role')
        email = data.get('email')
        username = data.get('username')
        
        # Check if user already exists
        existing_user = supabase.table('users').select('*').eq('email', email).execute()
        if existing_user.data:
            return jsonify({'message': 'User already exists'}), 400

        # Hash password
        hashed_password = generate_password_hash(data.get('password'))
        
        # Prepare user data
        user_data = {
            'id': str(uuid.uuid4()),
            'full_name': data.get('fullName'),
            'username': username,
            'email': email,
            'password': hashed_password,
            'role': role
        }

        # Additional data for instructors
        if role == 'instructor':
            user_data.update({
                'subject': data.get('subject'),
                'qualification': data.get('qualification'),
                'verification_code': data.get('verification'),
                'approval_status': 'pending'
            })

        try:
            # Insert user into database
            result = supabase.table('users').insert(user_data).execute()
            return jsonify({'message': 'Registration successful'}), 201

        except Exception as e:
            return jsonify({'message': str(e)}), 500

    @app.route('/login/<user_type>', methods=['POST', 'OPTIONS'])
    def login(user_type):
        app.logger.debug(f"Login attempt for user_type: {user_type}")
        if request.method == 'OPTIONS':
            response = jsonify({'status': 'ok'})
            response.headers['Access-Control-Allow-Origin'] = 'http://localhost:5000'
            response.headers['Access-Control-Allow-Methods'] = 'POST, OPTIONS'
            response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, Accept'
            response.headers['Access-Control-Allow-Credentials'] = 'true'
            response.headers['Access-Control-Max-Age'] = '86400'
            return response, 200

        try:
            data = request.json
            app.logger.debug(f'Login request data: {data}')
            
            email = data.get('email')
            password = data.get('password')

            if not all([email, password]):
                return jsonify({'message': 'Missing required fields'}), 400

            # Check for admin login
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
                        'message': 'Login successful'
                    }), 200
                return jsonify({'message': 'Invalid admin credentials'}), 401

            # Query Supabase for user
            app.logger.debug(f'Querying Supabase for user: {email} with role: {user_type}')
            user_query = supabase.table('users').select('*').eq('email', email).eq('role', user_type).execute()
            app.logger.debug(f'Supabase query result: {user_query.data}')
            
            if not user_query.data:
                return jsonify({'message': 'User not found'}), 404

            user = user_query.data[0]

            # Verify password
            if not check_password_hash(user['password'], password):
                return jsonify({'message': 'Invalid credentials'}), 401

            # For instructors, check approval status
            if user_type == 'instructor' and user.get('approval_status') != 'approved':
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
                'userType': user_type,
                'message': 'Login successful'
            }), 200

        except Exception as e:
            app.logger.error(f'Login error: {str(e)}')
            return jsonify({'message': f'Login failed: {str(e)}'}), 500

    # Log all registered routes after they're set up
    log_routes()
    
    return app

if __name__ == '__main__':
    app = create_app()
    app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))
