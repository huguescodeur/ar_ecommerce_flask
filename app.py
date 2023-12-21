from datetime import datetime, timedelta
import json
import secrets

import requests
from flask import Flask, jsonify, request, session
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_login import login_required


import random
import string
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:''@localhost/ardb'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'Hugues Codeur'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
CORS(app, supports_credentials=True)
# ? Initialisation du gestionnaire de connexion
login_manager = LoginManager(app)
login_manager.init_app(app)
login_manager.login_view = 'login'

# Configurez votre clé d'API SendGrid
sendgrid_api_key = "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"

# ? Configuration Flask-Mail
app.config['SENDGRID_API_KEY'] = sendgrid_api_key
sendgrid = SendGridAPIClient(app.config['SENDGRID_API_KEY'])
# mail = Mail(app)


# ? Configure Flask-Mail to use OAuth 2.0 credentials
# mail.init_app(app)
# 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

with app.app_context():
    db.create_all()


# ? Création du modèle SQLAlchemy pour les utilisateurs
class User(db.Model, UserMixin):
    id_user = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    # token = db.Column(db.String(500), nullable=True)

    # Ajoutez cette méthode pour permettre à Flask-Login de récupérer l'identifiant de l'utilisateur
    def get_id(self):
        return str(self.id_user)

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password)

    def verify_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

    def is_active(self):
        return True

    def __repr__(self):
        return '<Name %r>' % self.username


# ? Fonction pour générer un code de confirmation
def generate_confirmation_code():
    return ''.join(random.choices(string.digits, k=5))


# ? Dictionnaire temporaire pour stocker les informations d'inscription en attente de confirmation
temp_user_data = {}


# ? Fonction user_loader
@login_manager.user_loader
def load_user(user_id):
    # Utilisez la fonction de votre modèle User pour récupérer l'utilisateur à partir de l'ID
    return User.query.get(int(user_id))


@app.route('/')
def hello_world():  # put application's code here
    return 'Hello World!'


# ! Gestion Back-End User
# ? Login user
@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()

    email = data.get('email')
    password = data.get('password')

    try:
        # Récupérons l'utilisateur depuis la base de données
        user = User.query.filter_by(email=email).first()

        if user is None:
            response_data = {'message': 'Email ou mot de passe incorrect'}
            return jsonify(response_data), 401

        if user and user.verify_password(password):
            # Si le mot de passe est correct, enregistrons l'utilisateur dans la session
            login_user(user)
            print(login_user(user))

            # Stockons les informations de l'utilisateur dans la session
            session['user_data'] = {
                'id': user.id_user,
                'username': user.username,
                'email': user.email
            }

            # Construisons la réponse au format JSON
            response_data = {
                'message': 'Connexion réussie'}
            return jsonify(response_data), 200
        else:
            # Construisons la réponse au format JSON pour les échecs de connexion
            response_data = {
                'message': 'Nom d\'utilisateur ou mot de passe incorrect'}
            return jsonify(response_data), 401
    except Exception as e:
        # En cas d'erreur inattendue, renvoyer une réponse JSON avec un code d'erreur
        response_data = {
            'message': 'Erreur interne du serveur', 'error': str(e)}
        return jsonify(response_data), 500


# ? Route pour obtenir les informations de l'utilisateur actuellement connecté
@app.route("/current-user", methods=["GET", "POST"])
def get_current_user():
    if current_user.is_authenticated:
        # Assurez-vous que l'utilisateur est authentifié
        print(current_user.is_authenticated)
        print(current_user.id_user)
        user_data = {
            'id': current_user.id_user,
            'username': current_user.username,
            'email': current_user.email
        }

        print(user_data)
        return jsonify(user_data), 200
    elif 'user_data' in session:
        user_data = session['user_data']
        print(user_data)
        return jsonify(user_data), 200
    else:
        return jsonify({'error': 'User not authenticated'}), 401


# ? Register
@app.route("/register", methods=['POST'])
def register():
    data = request.get_json()

    print(data)

    username = data.get('username')
    email = data.get('email')
    password = data.get('password')

    existing_email = User.query.filter_by(email=email).first()

    if existing_email:
        return jsonify(
            {'error': 'Email already exists. Please use a different email address.'}), 409

    # ? Générer un code de confirmation
    confirmation_code = generate_confirmation_code()

    # ? Stocker temporairement les informations d'inscription
    temp_user_data[email] = {
        'username': username,
        'password': password,
        'confirmation_code': confirmation_code,
        'confirmation_code_expiration': datetime.now() + timedelta(minutes=10)
    }

    # ? Envoyer l'e-mail de confirmation avec SendGrid
    sender_email = "huguescodeur@gmail.com"

    message = Mail(
        from_email=sender_email,
        to_emails=email,
        subject='Confirmation Code AR Ecommerce',
        plain_text_content=f'Votre code de confirmation est : {
            confirmation_code}'
    )

    try:
        # Initialisez l'API SendGrid
        sg = SendGridAPIClient(sendgrid_api_key)

        # Envoyez le message
        response = sg.send(message)

        return app.response_class(
            response=json.dumps(
                {'message': 'Un code de confirmation a été envoyé par e-mail.'}),
            status=200,
            mimetype='application/json'
        )

    except Exception as e:
        error_message = "An error occurred during registration. Please try again."
        print(f"Error during registration: {str(e)}")
        return jsonify({'error': error_message}), 500


# ? Route pour la vérification du code
@app.route("/verify-code", methods=['POST'])
def verify_code():
    data = request.get_json()

    email = data.get('email')
    entered_code = data.get('code')

    # Vérifiez si l'e-mail et le code sont présents dans temp_user_data
    if email in temp_user_data and 'confirmation_code' in temp_user_data[email]:
        stored_code = temp_user_data[email]['confirmation_code']
        expiration_time = temp_user_data[email]['confirmation_code_expiration']

        # Vérifier si le code entré correspond au code stocké et si le temps d'expiration n'est pas dépassé
        if entered_code == stored_code and datetime.now() <= expiration_time:
            # Générer un jeton sécurisé pour enregistrer l'utilisateur
            token = secrets.token_urlsafe(16)

            # Ajouter l'utilisateur à la base de données
            new_user = User(
                username=temp_user_data[email]['username'], email=email)
            new_user.set_password(temp_user_data[email]['password'])
            db.session.add(new_user)

            try:
                db.session.commit()
                login_user(new_user)
                return jsonify({'message': 'Registration successful. You are now logged in.'}), 200

            except Exception as e:
                db.session.rollback()
                print(f"Erreur lors de l'inscription: {str(e)}")
                return jsonify({'error': 'Une erreur s\'est produite lors de l\'inscription. Veuillez réessayer.'}), 500

        elif entered_code != stored_code:
            return jsonify({'error': 'Le code de confirmation est incorrect.'}), 400
        elif datetime.now() > expiration_time:
            return jsonify({'error': 'The confirmation code has expired. Please request a new one.'}), 400

    else:
        return jsonify({'error': 'L\'e-mail ou le code de confirmation est introuvable.'}), 404


# ? Route pour la déconnexion
@app.route("/logout", methods=["POST"])
def logout():
    try:
        # Déconnectez l'utilisateur actuel
        logout_user()
        return jsonify({'message': 'Vous êtes déconnecté.'}), 200
    except Exception as e:
        print(f"Erreur lors de la déconnexion : {str(e)}")

        return jsonify({'error': 'Une erreur s\'est produite lors de la déconnexion.'}), 500


if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
