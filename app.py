from datetime import datetime, timedelta
import json
import secrets


from flask import Flask, jsonify, request, make_response
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, jwt_required, get_jwt_identity
from flask_jwt_extended import create_access_token
from flask_login import LoginManager, UserMixin, logout_user
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS


import random
import string
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:''@localhost/ardb'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'Hugues Codeur'
app.config['JWT_SECRET_KEY'] = 'Hugues Codeur'

# ? Flask-Mail
# Configuration Flask-Mail
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = ''
app.config['MAIL_PASSWORD'] = ''

# mail = Mail(app)


# app.config['JWT_ACCESS_TOKEN_EXPIRES'] = None

db = SQLAlchemy(app)
jwt = JWTManager(app)
bcrypt = Bcrypt(app)
CORS(app, supports_credentials=True)
# ? Initialisation du gestionnaire de connexion
login_manager = LoginManager(app)
login_manager.init_app(app)
login_manager.login_view = 'login'


# Configurez votre clé d'API SendGrid
sendgrid_api_key = ""

# ? Configuration Flask-Mail
app.config['SENDGRID_API_KEY'] = sendgrid_api_key
sendgrid = SendGridAPIClient(app.config['SENDGRID_API_KEY'])
# mail = Mail(app)


# ? Configure Flask-Mail to use OAuth 2.0 credentials
# mail.init_app(app)


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
            user_data = {
                'id': user.id_user,
                'username': user.username,
                'email': user.email
            }
            # Si le mot de passe est correct, créons un token pour le user
            # Définir la durée de validité à 365 jours
            expires_delta = timedelta(days=365)
            access_token = create_access_token(
                identity=user_data, expires_delta=expires_delta)

            # Créez la réponse avec le cookie sécurisé
            response = make_response(jsonify(access_token=access_token), 200)

            # Définissez les options du cookie
            response.set_cookie('access_token', value=access_token,
                                secure=True, httponly=True, max_age=365 * 24 * 60 * 60)

            return response
        else:
            response_data = {
                'message': 'Nom d\'utilisateur ou mot de passe incorrect'}
            return jsonify(response_data), 401
    except Exception as e:
        response_data = {
            'message': 'Erreur interne du serveur', 'error': str(e)}
        return jsonify(response_data), 500


# # ? Login user
# @app.route("/login", methods=["POST"])
# def login():
#     data = request.get_json()

#     email = data.get('email')
#     password = data.get('password')

#     try:
#         # Récupérons l'utilisateur depuis la base de données
#         user = User.query.filter_by(email=email).first()

#         if user is None:
#             response_data = {'message': 'Email ou mot de passe incorrect'}
#             return jsonify(response_data), 401

#         if user and user.verify_password(password):
#             user_data = {
#                 'id': user.id_user,
#                 'username': user.username,
#                 'email': user.email
#             }
#             # Si le mot de passe est correct, créons un token pour le user
#             access_token = create_access_token(identity=user_data)
#             # print(access_token)
#             return jsonify(access_token=access_token), 200
#         else:
#             response_data = {
#                 'message': 'Nom d\'utilisateur ou mot de passe incorrect'}
#             return jsonify(response_data), 401
#     except Exception as e:
#         response_data = {
#             'message': 'Erreur interne du serveur', 'error': str(e)}
#         return jsonify(response_data), 500


# ? Route pour obtenir les informations de l'utilisateur actuellement connecté
@app.route("/current-user", methods=["GET", "POST"])
@jwt_required()
def get_current_user():
    try:
        # Obtenez l'ID utilisateur à partir du jeton d'accès
        user_id = get_jwt_identity()['id']

        # Recherchez l'utilisateur dans la base de données
        user = User.query.filter_by(id_user=user_id).first()

        if user:
            user_data = {
                'id': user.id_user,
                'username': user.username,
                'email': user.email
            }
            return jsonify(user_data), 200
        else:
            return jsonify({'error': 'User not found'}), 404

    except Exception as e:
        return jsonify({'error': 'Invalid token', 'details': str(e)}), 401


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
        'confirmation_code_expiration': datetime.now() + timedelta(minutes=20)
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

    if email in temp_user_data and 'confirmation_code' in temp_user_data[email]:
        stored_code = temp_user_data[email]['confirmation_code']
        expiration_time = temp_user_data[email]['confirmation_code_expiration']

        if entered_code == stored_code and datetime.now() <= expiration_time:
            new_user = User(
                username=temp_user_data[email]['username'], email=email)
            new_user.set_password(temp_user_data[email]['password'])
            db.session.add(new_user)

            try:
                db.session.commit()

                # Créez le jeton d'accès avec une expiration d'un an
                expires_delta = timedelta(days=365)
                user_data = {
                    'id': new_user.id_user,
                    'username': new_user.username,
                    'email': new_user.email
                }
                access_token = create_access_token(
                    identity=user_data, expires_delta=expires_delta)

                # Créez la réponse avec le cookie sécurisé
                response = make_response(
                    jsonify(access_token=access_token), 200)

                # Définissez les options du cookie
                response.set_cookie('access_token', value=access_token,
                                    secure=True, httponly=True, max_age=365 * 24 * 60 * 60)

                return response

            except Exception as e:
                db.session.rollback()
                return jsonify({'error': 'Une erreur s\'est produite lors de l\'inscription. Veuillez réessayer.'}), 500

        elif entered_code != stored_code:
            return jsonify({'error': 'Le code de confirmation est incorrect.'}), 400
        elif datetime.now() > expiration_time:
            return jsonify({'error': 'Le code de confirmation a expiré. Veuillez en demander un nouveau.'}), 400

    else:
        return jsonify({'error': 'L\'e-mail ou le code de confirmation est introuvable.'}), 404

# @app.route("/verify-code", methods=['POST'])
# def verify_code():
#     data = request.get_json()

#     email = data.get('email')
#     entered_code = data.get('code')

#     # ? Vérifiez si l'e-mail et le code sont présents dans temp_user_data
#     if email in temp_user_data and 'confirmation_code' in temp_user_data[email]:
#         stored_code = temp_user_data[email]['confirmation_code']
#         expiration_time = temp_user_data[email]['confirmation_code_expiration']

#         # ? Vérifier si le code entré correspond au code stocké et si le temps d'expiration n'est pas dépassé
#         if entered_code == stored_code and datetime.now() <= expiration_time:

#             # ? Ajouter l'utilisateur à la base de données
#             new_user = User(
#                 username=temp_user_data[email]['username'], email=email)
#             new_user.set_password(temp_user_data[email]['password'])
#             db.session.add(new_user)

#             try:
#                 db.session.commit()
#                 # login_user(new_user)
#                 # return jsonify({'message': 'Registration successful. You are now logged in.'}), 200
#                 # Créer un jeton d'accès pour l'utilisateur
#                 # Le token expire dans 1 an, ajustez selon vos besoins
#                 expires_delta = timedelta(days=365)
#                 user_data = {
#                     'id': new_user.id_user,
#                     'username': new_user.username,
#                     'email': new_user.email
#                 }
#                 access_token = create_access_token(
#                     identity=user_data, expires_delta=expires_delta)
#                 return jsonify(access_token=access_token), 200

#             except Exception as e:
#                 db.session.rollback()
#                 print(f"Erreur lors de l'inscription: {str(e)}")
#                 return jsonify({'error': 'Une erreur s\'est produite lors de l\'inscription. Veuillez réessayer.'}), 500

#         elif entered_code != stored_code:
#             return jsonify({'error': 'Le code de confirmation est incorrect.'}), 400
#         elif datetime.now() > expiration_time:
#             return jsonify({'error': 'The confirmation code has expired. Please request a new one.'}), 400

#     else:
#         return jsonify({'error': 'L\'e-mail ou le code de confirmation est introuvable.'}), 404


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
