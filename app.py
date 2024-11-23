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
    
    # Configure CORS to allow requests from your frontend
    CORS(app, resources={
        r"/*": {
            "origins": ["https://elimu-global-testing.onrender.com", "http://localhost:3000"],
            "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
            "allow_headers": ["Content-Type", "Authorization"]
        }
    })

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

    @app.route('/api/auth/signin/<user_type>', methods=['POST'])
    def login(user_type):
        data = request.json
        email = data.get('email')
        password = data.get('password')

        # Check for admin login
        if user_type == 'admin':
            if (email == ADMIN_CREDENTIALS['email'] and 
                check_password_hash(ADMIN_CREDENTIALS['password'], password)):
                token = generate_jwt_token('admin')
                return jsonify({
                    'token': token, 
                    'redirect': '/admin-dashboard'
                }), 200
            return jsonify({'message': 'Invalid admin credentials'}), 401

        # Regular user login
        try:
            user = supabase.table('users').select('*').eq('email', email).eq('role', user_type).execute()
            
            if not user.data:
                return jsonify({'message': 'User not found'}), 404
            
            user_data = user.data[0]
            
            # Check password
            if not check_password_hash(user_data['password'], password):
                return jsonify({'message': 'Invalid credentials'}), 401
            
            # Check instructor approval if applicable
            if user_type == 'instructor' and user_data.get('approval_status') != 'approved':
                return jsonify({'message': 'Instructor account pending approval'}), 403
            
            # Generate token
            token = generate_jwt_token(user_type, user_data['id'])
            
            # Determine redirect based on role
            redirects = {
                'student': '/student-dashboard',
                'instructor': '/instructor-dashboard'
            }
            
            return jsonify({
                'token': token, 
                'redirect': redirects.get(user_type, '/')
            }), 200

        except Exception as e:
            return jsonify({'message': str(e)}), 500

    def generate_jwt_token(role, user_id=None):
        payload = {
            'role': role,
            'exp': datetime.utcnow() + timedelta(hours=24)
        }
        if user_id:
            payload['user_id'] = user_id
        
        return jwt.encode(payload, SECRET_KEY, algorithm='HS256')

    # Add a health check endpoint for deployment
    @app.route('/health', methods=['GET'])
    def health_check():
        return jsonify({'status': 'healthy'}), 200

    return app

if __name__ == '__main__':
    app = create_app()
    app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))