from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import uuid
from logsystem import LogSystem

game_name = 'TITELNAMEGAME'
api_version = '0.0.1'
uuid_salt = 'your_salt_value'

app = Flask(__name__)
LogSystem = LogSystem()

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///game_shop.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.String(36), primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    secret = db.Column(db.String(36), unique=True, nullable=False)
    data = db.Column(db.JSON, default={})
    coins = db.Column(db.Integer, default=0)


class PurchaseHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False)
    product_name = db.Column(db.String(100), nullable=False)
    purchase_date = db.Column(db.DateTime, nullable=False)


with app.app_context():
    db.create_all()
    LogSystem.log_info("Database tables created")


@app.route('/')
def index():
    LogSystem.log_info("Index route accessed")
    return {'name': f'ShopAPI - {game_name}', 'version': api_version}


@app.route('/account', methods=['POST', 'GET'])
def account():
    if request.method == 'POST':
        try:
            data = request.json
            username = data['username']
            password = data['password']

            if User.query.filter_by(username=username).first():
                LogSystem.log_warning(f"Account creation failed: Username '{username}' already exists")
                return jsonify({'error': 'Username already exists'}), 400

            hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
            secret = str(uuid.uuid5(uuid.NAMESPACE_DNS, uuid_salt + str(uuid.uuid4())))

            user_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, uuid_salt + str(uuid.uuid4())))
            new_user = User(id=user_id, username=username, password=hashed_password, secret=secret)
            LogSystem.log_info(f"Created user: {username} with hashed password: {hashed_password}")
            db.session.add(new_user)
            LogSystem.log_info(f"New user '{username}' successfully added to the database with ID: {user_id}")
            db.session.commit()

            LogSystem.log_info(f"Account created successfully for user: {username}")
            return jsonify({'message': 'Account created successfully', 'user_id': user_id, 'secret': secret}), 201
        except Exception as e:
            LogSystem.log_error(f"Error creating account: {str(e)}. Request data: {request.json}")
            return jsonify({'error': str(e)}), 500

    elif request.method == 'GET':
        try:
            user_id = request.args.get('user_id')
            secret = request.args.get('secret')
            password = request.args.get('password')

            if not user_id or (not secret and not password):
                LogSystem.log_warning("Access denied: Missing required credentials")
                return jsonify({'error': 'Access denied: Missing required credentials'}), 401

            user = User.query.get(user_id)

            if not user:
                LogSystem.log_warning(f"User not found: {user_id}")
                return jsonify({'error': 'User not found'}), 404

            if secret and user.secret == secret:
                LogSystem.log_info(f"Account info retrieved for user: {user.username}")
                return jsonify({
                    'username': user.username,
                    'coins': user.coins,
                    'purchases': [
                        {
                            'product_name': ph.product_name,
                            'purchase_date': ph.purchase_date.isoformat()
                        } for ph in PurchaseHistory.query.filter_by(user_id=user_id).all()
                    ]
                }), 200

            if password and check_password_hash(user.password, password):
                LogSystem.log_info(f"Account info retrieved for user: {user.username}")
                return jsonify({
                    'username': user.username,
                    'coins': user.coins,
                    'purchases': [
                        {
                            'product_name': ph.product_name,
                            'purchase_date': ph.purchase_date.isoformat()
                        } for ph in PurchaseHistory.query.filter_by(user_id=user_id).all()
                    ]
                }), 200

            LogSystem.log_warning(f"Access denied: Invalid credentials for user: {user_id}")
            return jsonify({'error': 'Access denied: Invalid credentials'}), 401

        except Exception as e:
            LogSystem.log_error(f"Error fetching account info: {str(e)}")
            return jsonify({'error': str(e)}), 500


@app.route('/coins', methods=['GET', 'PUT'])
def coins():
    if request.method == 'GET':
        try:
            user_id = request.args.get('user_id')
            secret = request.args.get('secret')
            password = request.args.get('password')

            if not user_id or (not secret and not password):
                LogSystem.log_warning("Access denied: Missing required credentials")
                return jsonify({'error': 'Access denied: Missing required credentials'}), 401

            user = User.query.get(user_id)

            if not user:
                LogSystem.log_warning(f"User not found: {user_id}")
                return jsonify({'error': 'User not found'}), 404

            if secret and user.secret == secret:
                LogSystem.log_info(f"Coins info retrieved for user: {user.username}")
                return jsonify({'coins': user.coins}), 200

            if password and check_password_hash(user.password, password):
                LogSystem.log_info(f"Coins info retrieved for user: {user.username}")
                return jsonify({'coins': user.coins}), 200

            LogSystem.log_warning(f"Access denied: Invalid credentials for user: {user_id}")
            return jsonify({'error': 'Access denied: Invalid credentials'}), 401

        except Exception as e:
            LogSystem.log_error(f"Error fetching coins info: {str(e)}")
            return jsonify({'error': str(e)}), 500

    elif request.method == 'PUT':
        try:
            data = request.json
            user_id = data['user_id']
            secret = data.get('secret')
            action = data['action']
            amount = data['amount']

            user = User.query.get(user_id)
            if not user or user.secret != secret:
                LogSystem.log_warning(f"Unauthorized access attempt for user: {user_id}")
                return jsonify({'error': 'Unauthorized'}), 401

            if action == 'add':
                user.coins += amount
                LogSystem.log_info(f"Added {amount} coins to user: {user.username}. Total coins: {user.coins}")
            elif action == 'deduct':
                if user.coins < amount:
                    LogSystem.log_warning(f"Not enough coins for user: {user.username}. Attempted to deduct: {amount}")
                    return jsonify({'error': 'Not enough coins'}), 400
                user.coins -= amount
                LogSystem.log_info(f"Deducted {amount} coins from user: {user.username}. Total coins: {user.coins}")
            else:
                LogSystem.log_warning(f"Invalid action: {action} for user: {user.username}")
                return jsonify({'error': 'Invalid action'}), 400

            db.session.commit()
            LogSystem.log_info(
                f"User '{user.id}' coins updated: Action='{action}', Amount={amount}. Total={user.coins}")
            return jsonify({'message': 'Coins updated successfully', 'coins': user.coins}), 200
        except Exception as e:
            LogSystem.log_error(f"Error updating coins: {str(e)}.")
            return jsonify({'error': str(e)}), 500


@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.json
        username = data['username']
        password = data['password']

        user = User.query.filter_by(username=username).first()
        if not user:
            LogSystem.log_info(f"Login attempt failed. User not found: {username}")
            return jsonify({'error': 'User not found'}), 404
        if not check_password_hash(user.password, password):
            LogSystem.log_info(f"Login attempt failed. Invalid password for user: {username}")
            return jsonify({'error': 'Invalid username or password'}), 401

        LogSystem.log_info(f"User '{username}' logged in successfully")
        return jsonify(
            {'message': 'Login successful', 'username': username, 'user_id': user.id, 'secret': user.secret}), 200
    except Exception as e:
        LogSystem.log_error(f"Error during login: {str(e)}. Request data: {request.json}")
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    app.run()
