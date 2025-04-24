# -------------------- IMPORTS --------------------
from flask import Flask, render_template, request, redirect, url_for, session, flash
import numpy as np
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
import os
from itsdangerous import URLSafeTimedSerializer
from dotenv import load_dotenv
import re

# -------------------- CONFIGURATION --------------------
app = Flask(__name__)
load_dotenv()

# Configuration des variables sensibles
app.secret_key = os.getenv("SECRET_KEY", "default_secret_key")  # Ajout d'une valeur par défaut
MAIL_USERNAME = "khadijazeroual902@gmail.com"  # Email fourni
MAIL_PASSWORD = "kjxvqnbqkmcnztap"  # Mot de passe fourni
MAIL_SERVER = "smtp.gmail.com"
MAIL_PORT = 587
MAIL_USE_TLS = True
MAIL_DEFAULT_SENDER = MAIL_USERNAME

# Initialisation du sérialiseur pour les tokens
serializer = URLSafeTimedSerializer(app.secret_key)

# -------------------- FONCTIONS UTILITAIRES --------------------
def init_db():
    """Initialise la base de données SQLite"""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute("DROP TABLE IF EXISTS users")
    cursor.execute('''CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        username TEXT UNIQUE,
        password TEXT NOT NULL
    )''')
    conn.commit()
    conn.close()

def get_db_connection():
    """Établit une connexion à la base de données"""
    return sqlite3.connect('users.db', timeout=10)

def is_valid_password(password):
    """Valide le mot de passe selon des critères spécifiques"""
    return (len(password) >= 8 and
            re.search(r'[A-Z]', password) and
            re.search(r'[a-zA-Z]', password) and
            re.search(r'[^\w\s]', password))

def send_reset_email(email, token):
    """Envoie un email de réinitialisation de mot de passe"""
    reset_url = f"{request.host_url}reset-password/{token}"
    body = f"Cliquez sur ce lien pour réinitialiser votre mot de passe:\n\n{reset_url}"
    
    msg = MIMEMultipart()
    msg['From'] = MAIL_DEFAULT_SENDER
    msg['To'] = email
    msg['Subject'] = "Réinitialisation de mot de passe"
    msg.attach(MIMEText(body, 'plain'))
    
    try:
        with smtplib.SMTP(MAIL_SERVER, MAIL_PORT) as server:
            server.starttls()
            server.login(MAIL_USERNAME, MAIL_PASSWORD)
            server.send_message(msg)
        return True
    except Exception as e:
        print(f"Erreur d'envoi d'email: {e}")
        return False

def calcul_diffusion(x_A, D_AB0, D_BA0, phi_A, phi_B, lambda_A, lambda_B,
                    theta_BA, theta_AB, theta_AA, theta_BB, tau_AB, tau_BA,
                    q_A, q_B):
    """Calcule le coefficient de diffusion"""
    x_B = 1 - x_A
    ln_D_AB0 = np.log(D_AB0)
    ln_D_BA0 = np.log(D_BA0)

    # Calcul des différents termes
    first_term = x_B * ln_D_AB0 + x_A * ln_D_BA0
    second_term = 2 * (x_A * np.log(x_A / phi_A) + x_B * np.log(x_B / phi_B))
    third_term = 2 * x_A * x_B * (
        (phi_A / x_A) * (1 - lambda_A / lambda_B) +
        (phi_B / x_B) * (1 - lambda_B / lambda_A)
    )
    fourth_term = x_B * q_A * (
        (1 - theta_BA**2) * np.log(tau_BA) +
        (1 - theta_BB**2) * np.log(tau_AB) * tau_AB
    )
    fifth_term = x_A * q_B * (
        (1 - theta_AB**2) * np.log(tau_AB) +
        (1 - theta_AA**2) * np.log(tau_BA) * tau_BA
    )

    # Calcul final
    ln_D_AB = first_term + second_term + third_term + fourth_term + fifth_term
    D_AB = np.exp(ln_D_AB)
    correction_factor = 1.0163
    D_AB_corrige = D_AB * correction_factor
    error = 1.6

    return D_AB_corrige, error

# -------------------- ROUTES PRINCIPALES --------------------
@app.route('/')
def home():
    """Page d'accueil"""
    image_url = 'https://daily.kellogg.edu/wp-content/uploads/2018/04/chemistry.jpg'
    css_file = 'static/styles.css'
    return render_template('home.html', image_url=image_url, css_file=css_file, design_link=url_for('design_showcase'))

@app.route('/design-showcase')
def design_showcase():
    """Page de démonstration du design"""
    return render_template('design_showcase.html')

@app.route('/auth-redirect')
def auth_redirect():
    """Redirection après authentification"""
    if 'username' in session:
        return redirect(url_for('calculate'))
    return redirect(url_for('login_choice'))

# -------------------- ROUTES D'AUTHENTIFICATION --------------------
@app.route('/login-choice')
def login_choice():
    """Page de choix de connexion"""
    return render_template('auth/login_choice.html')

# Store failed attempts and lockout time in memory (for simplicity)
failed_attempts = {}
lockout_duration = timedelta(minutes=5)

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Gère la connexion des utilisateurs"""
    global failed_attempts
    user_ip = request.remote_addr
    lockout_time = None

    # Check if the user is locked out
    if user_ip in failed_attempts:
        attempts, last_attempt = failed_attempts[user_ip]
        if attempts >= 3 and datetime.now() - last_attempt < lockout_duration:
            lockout_time = (lockout_duration - (datetime.now() - last_attempt)).seconds // 60
            return render_template('auth/login.html', lockout_time=lockout_time)

    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        if not email or not password:
            flash("L'email et le mot de passe sont obligatoires.", "warning")
            return render_template('auth/login.html')

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT password FROM users WHERE email = ?", (email,))
        user = cursor.fetchone()
        conn.close()

        if user and check_password_hash(user[0], password):
            session['username'] = email  # Connecter l'utilisateur avec l'email
            flash("Connexion réussie !", "success")
            failed_attempts.pop(user_ip, None)  # Reset failed attempts on success
            return redirect(url_for('calculate'))
        else:
            flash("Email ou mot de passe incorrect.", "danger")
            # Track failed attempts
            if user_ip not in failed_attempts:
                failed_attempts[user_ip] = [1, datetime.now()]
            else:
                failed_attempts[user_ip][0] += 1
                failed_attempts[user_ip][1] = datetime.now()

    return render_template('auth/login.html', lockout_time=lockout_time)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    """Gère l'inscription des nouveaux utilisateurs"""
    if request.method == 'POST':
        email = request.form.get('email')
        username = request.form.get('username')  # Nom d'utilisateur optionnel
        password = request.form.get('password')

        if not email or not password:
            flash("L'email et le mot de passe sont obligatoires.", "warning")
            return render_template('auth/signup.html')

        if not is_valid_password(password):
            flash("Le mot de passe doit contenir au moins 8 caractères, une majuscule et un caractère spécial.", "danger")
            return render_template('auth/signup.html')

        hashed_password = generate_password_hash(password)
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("INSERT INTO users (email, username, password) VALUES (?, ?, ?)", 
                           (email, username, hashed_password))
            conn.commit()
            conn.close()
            session['username'] = email  # Connecter automatiquement l'utilisateur avec l'email
            flash("Inscription réussie !", "success")
            return redirect(url_for('calculate'))  # Rediriger vers la page de calcul
        except sqlite3.IntegrityError:
            flash("L'email est déjà utilisé.", "danger")
            return render_template('auth/signup.html')

    return render_template('auth/signup.html')

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    """Gère la demande de réinitialisation de mot de passe"""
    if request.method == 'POST':
        email = request.form.get('email')

        if not email:
            flash("Veuillez entrer une adresse email.", "warning")
            return render_template('auth/forgot_password.html')

        # Vérifier si l'email existe dans la base de données
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM users WHERE email = ?", (email,))
        user = cursor.fetchone()
        conn.close()

        if user:
            # Générer un token sécurisé
            token = serializer.dumps(email, salt='password-reset-salt')

            # Envoyer l'email avec le token
            if send_reset_email(email, token):
                flash("Un email de réinitialisation a été envoyé.", "success")
            else:
                flash("Erreur lors de l'envoi de l'email. Veuillez réessayer.", "danger")
        else:
            flash("Aucun compte associé à cet email.", "warning")

    return render_template('auth/forgot_password.html')

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    """Gère la réinitialisation du mot de passe"""
    try:
        email = serializer.loads(token, salt='password-reset-salt', max_age=3600)  # Token valide pendant 1 heure
    except Exception as e:
        flash("Le lien de réinitialisation est invalide ou a expiré.", "danger")
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        new_password = request.form.get('password')

        if not new_password or not is_valid_password(new_password):
            flash("Veuillez entrer un mot de passe valide.", "warning")
            return render_template('auth/reset_password.html', token=token)

        # Mettre à jour le mot de passe dans la base de données
        hashed_password = generate_password_hash(new_password)
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET password = ? WHERE email = ?", (hashed_password, email))
        conn.commit()
        conn.close()

        flash("Votre mot de passe a été réinitialisé avec succès.", "success")
        return redirect(url_for('login'))

    return render_template('auth/reset_password.html', token=token)

@app.route('/logout')
def logout():
    """Déconnecte l'utilisateur"""
    session.clear()
    flash("Vous avez été déconnecté avec succès.", "info")
    return redirect(url_for('login_choice'))

# -------------------- ROUTES DE CALCUL --------------------
@app.route('/calculate', methods=['GET', 'POST'])
def calculate():
    """Page de calcul du coefficient de diffusion"""
    if 'username' not in session:
        flash("Vous devez être connecté pour accéder au calculateur.", "warning")
        return redirect(url_for('login_choice'))

    result = error_value = error_message = None

    if request.method == 'POST':
        try:
            # Récupération des paramètres du formulaire
            params = {
                'x_A': float(request.form.get('x_A', 0.45)),
                'D_AB0': float(request.form.get('D_AB0', 1.2e-5)),
                'D_BA0': float(request.form.get('D_BA0', 1.1e-5)),
                'phi_A': float(request.form.get('phi_A', 0.5)),
                'phi_B': float(request.form.get('phi_B', 0.5)),
                'lambda_A': float(request.form.get('lambda_A', 1.0)),
                'lambda_B': float(request.form.get('lambda_B', 1.0)),
                'theta_BA': float(request.form.get('theta_BA', 0.1)),
                'theta_AB': float(request.form.get('theta_AB', 0.1)),
                'theta_AA': float(request.form.get('theta_AA', 0.1)),
                'theta_BB': float(request.form.get('theta_BB', 0.1)),
                'tau_AB': float(request.form.get('tau_AB', 1.0)),
                'tau_BA': float(request.form.get('tau_BA', 1.0)),
                'q_A': float(request.form.get('q_A', 1.0)),
                'q_B': float(request.form.get('q_B', 1.0)),
            }

            # Calcul du coefficient
            result, error_value = calcul_diffusion(**params)
            print(f"Calcul réussi: result={result}, error_value={error_value}")

        except ValueError as e:
            error_message = f"Erreur de saisie: {str(e)}"
            print(error_message)
        except Exception as e:
            error_message = f"Erreur de calcul: {str(e)}"
            print(error_message)

    print(f"Rendering template with result={result}, error_value={error_value}, error_message={error_message}")
    return render_template('calculate.html',
                         username=session.get('username'),
                         result=result,
                         error_value=error_value,
                         error_message=error_message)

# -------------------- LANCEMENT DE L'APPLICATION --------------------
if __name__ == '__main__':
    init_db()  # Initialisation de la base de données
    app.run(host='127.0.0.1', port=5000, debug=True)  # Assurez-vous que debug=True