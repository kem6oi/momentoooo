from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    abort,
    jsonify,
    make_response,
    flash,
)
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_wtf.csrf import CSRFProtect
from core.auth.session import create_session, destroy_session, is_authenticated
from core.auth.rate_limit import rate_limit
from core.marketplace.models import Buyer, Seller
from routes.marketplace import marketplace_bp
from routes.auth import auth_bp
from routes.admin import admin_bp
from routes.profile import profile_bp
from core.auth.models import User
from core.database import db_session, init_db
from core.email.service import mail
from core.payment.service import init_stripe
from core.shared import challenge_manager
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
import os
import base64
from config.security_headers import add_security_headers

# Load environment variables
load_dotenv()

app = Flask(__name__)

# Add security headers to all responses
add_security_headers(app)

# Configure app
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS', 'True').lower() == 'true'
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER')
app.config["SESSION_TYPE"] = "filesystem"

# Initialize Flask-Mail
mail.init_app(app)

# Stripe configuration
app.config['STRIPE_PUBLIC_KEY'] = os.getenv('STRIPE_PUBLIC_KEY')
app.config['STRIPE_SECRET_KEY'] = os.getenv('STRIPE_SECRET_KEY')
app.config['STRIPE_WEBHOOK_SECRET'] = os.getenv('STRIPE_WEBHOOK_SECRET')

# Initialize CSRF protection
csrf = CSRFProtect(app)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'user_login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.filter_by(username=user_id).first()

# Register blueprints
app.register_blueprint(auth_bp)
app.register_blueprint(admin_bp)
app.register_blueprint(marketplace_bp)
app.register_blueprint(profile_bp)

# Initialize database
init_db()

# --- Initialize default challenges here, to make sure they exists at startup ---
try:
    challenge_manager.create_challenge("aes_easy", "aes", "easy")
    challenge_manager.create_challenge("vigenere_medium", "vigenere", "medium")
    challenge_manager.create_challenge("rsa_hard", "rsa", "hard")
except ValueError as e:
    print(f"Challenge creation error: {e}")  

# --- Authentication ---
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        email = request.form.get("email")  # Get email from form
        
        if User.query.filter_by(username=username).first():
            flash("Username already exists", "error")
            return render_template("register.html")
        
        user = User(
            username=username,
            password=generate_password_hash(password),
            email=email
        )
        db_session.add(user)
        db_session.commit()
        
        login_user(user)
        flash("Registration successful!", "success")
        return redirect(url_for("list_challenges"))
    
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def user_login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password, password):
            login_user(user)
            flash("Login successful!", "success")
            return redirect(url_for("list_challenges"))
        
        flash("Invalid credentials", "error")
    
    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    destroy_session()
    flash("You have been logged out", "info")
    return redirect(url_for("index"))


# --- Challenge Routes ---
@app.route("/challenges", methods=["GET"])
@login_required
def list_challenges():
    """List all available challenges."""
    verification_mode = request.args.get('mode', None)
    challenges = challenge_manager.get_all_challenges()
    
    if verification_mode == 'buyer':
        # Filter for easy challenges only
        challenges = {k: v for k, v in challenges.items() if v['difficulty'] == 'easy'}
        buyer = Buyer.query.filter_by(user_id=current_user.id).first()
        if buyer:
            solved_challenges = sum(1 for c in challenges.values() if c['id'] in buyer.solved_challenges)
            progress = f"{solved_challenges}/3 easy challenges completed"
        else:
            progress = "0/3 easy challenges completed"
    elif verification_mode == 'seller':
        # Filter for hard challenges only
        challenges = {k: v for k, v in challenges.items() if v['difficulty'] == 'hard'}
        seller = Seller.query.filter_by(user_id=current_user.id).first()
        if seller:
            solved_challenges = sum(1 for c in challenges.values() if c['id'] in seller.solved_challenges)
            progress = f"{solved_challenges}/5 hard challenges completed"
        else:
            progress = "0/5 hard challenges completed"
    else:
        progress = None

    return render_template('challenges.html', 
                         challenges=challenges,
                         verification_mode=verification_mode,
                         progress=progress)

@app.route("/challenge/<challenge_id>", methods=["GET"])
@login_required
def view_challenge(challenge_id):
    """View a specific challenge."""
    challenge = challenge_manager.get_challenge(challenge_id)
    if not challenge:
        abort(404)
    
    verification_mode = request.args.get('mode', None)
    if verification_mode == 'buyer' and challenge['difficulty'] != 'easy':
        flash('Buyers can only attempt easy challenges for verification.', 'error')
        return redirect(url_for('list_challenges', mode='buyer'))
    elif verification_mode == 'seller' and challenge['difficulty'] != 'hard':
        flash('Sellers can only attempt hard challenges for verification.', 'error')
        return redirect(url_for('list_challenges', mode='seller'))

    return render_template('challenge.html',
                         challenge=challenge,
                         verification_mode=verification_mode)

@app.route("/challenge/<challenge_id>", methods=["POST"])
@rate_limit
@login_required
def submit_flag(challenge_id):
    """Submit a flag for a challenge."""
    flag = request.form.get('flag')
    if not flag:
        flash('Please provide a flag.', 'error')
        return redirect(url_for('view_challenge', challenge_id=challenge_id))

    success, message = challenge_manager.submit_flag(challenge_id, current_user.username, flag)
    flash(message, 'success' if success else 'error')

    if success:
        # Update user's solved challenges
        verification_mode = request.args.get('mode', None)
        if verification_mode == 'buyer':
            buyer = Buyer.query.filter_by(user_id=current_user.id).first()
            if buyer:
                buyer.add_solved_challenge(challenge_id)
                db_session.commit()
                # Check if buyer has completed enough challenges
                if buyer.is_verified >= 3:
                    flash('Congratulations! You have completed enough challenges to view products.', 'success')
                    return redirect(url_for('marketplace.view_products'))
        elif verification_mode == 'seller':
            seller = Seller.query.filter_by(user_id=current_user.id).first()
            if seller:
                seller.add_solved_challenge(challenge_id)
                db_session.commit()
                # Check if seller has completed enough challenges
                if seller.is_verified >= 5:
                    flash('Congratulations! You have completed enough challenges to sell products.', 'success')
                    return redirect(url_for('marketplace.create_product'))

    return redirect(url_for('view_challenge', challenge_id=challenge_id))

@app.route("/challenge/<challenge_id>/hint", methods=["POST"])
@login_required
def show_hint(challenge_id):
    """Show a hint for a challenge."""
    hint, message = challenge_manager.use_hint(challenge_id, current_user.username)
    flash(message, 'info' if hint else 'error')
    return redirect(url_for('view_challenge', challenge_id=challenge_id))


# --- Index ---
@app.route("/")
def index():
    return render_template("index.html")

@app.teardown_appcontext
def shutdown_session(exception=None):
    db_session.remove()

if __name__ == "__main__":
    # Debug mode should only be enabled in development
    # Use environment variable to control debug mode
    debug_mode = os.getenv('FLASK_DEBUG', 'False').lower() == 'true'
    app.run(debug=debug_mode)  
