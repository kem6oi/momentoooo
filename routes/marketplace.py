# routes/marketplace.py

from flask import (
    Blueprint, render_template, request, flash, redirect, url_for,
    jsonify, send_from_directory, abort, current_app # Added current_app for logging
)
from flask_login import login_required, current_user, login_user
# --- Assuming models are correctly defined ---
from core.marketplace.models import Seller, Product, Buyer, Payment, PaymentStatus, PaymentMethod
from core.auth.models import User # Assuming User model is here
# --- Assuming db_session is correctly configured ---
from core.database import db_session
# --- Assuming these exist and work ---
from core.challenges.challenge_manager import ChallengeManager
# --- Remove email verification import ---
# from core.email.service import send_verification_email
# --- Assuming payment functions exist elsewhere ---
# from core.payment.service import get_payment_methods, create_payment_method, delete_payment_method, process_payment

# --- Other necessary imports ---
from flask_wtf.csrf import CSRFProtect # Recommended to enable
from functools import wraps
import os
import traceback # For detailed error logging
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash
import uuid
import json
import stripe # If used directly
from uuid import uuid4
import magic
from datetime import datetime
from sqlalchemy import func # For potential aggregate queries like total_sales

# --- Define Blueprint FIRST ---
marketplace_bp = Blueprint('marketplace', __name__, url_prefix='/marketplace')

# --- Other Setup (Constants, Helpers, Manager Instances) ---
# Consider moving these to app config if not already there
UPLOAD_FOLDER = 'uploads/products'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max file size

# Configure Stripe (ensure key is loaded correctly)
# Ensure this is done safely, preferably via app config from env vars
# stripe.api_key = os.getenv('STRIPE_SECRET_KEY') # Loaded in app.py usually

# Create upload folder if it doesn't exist
# This might be better done at app startup or using Flask commands
try:
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
except OSError as e:
    # Log this error if it happens during import time
    print(f"Error creating upload folder {UPLOAD_FOLDER}: {e}")


challenge_manager = ChallengeManager() # Instantiate manager
# csrf = CSRFProtect() # Initialize if enabling CSRF and initializing it here

# --- Helper Functions ---

def validate_image(stream):
    """Validate file is actually an image using python-magic"""
    try:
        mime = magic.Magic(mime=True)
        buffer = stream.read(2048)
        stream.seek(0) # Reset stream position crucial
        if not buffer: return None
        mime_type = mime.from_buffer(buffer)
        if not mime_type.startswith('image/'): return None
        mime_to_ext = {'image/jpeg': '.jpg', 'image/png': '.png', 'image/gif': '.gif', 'image/webp': '.webp'}
        return mime_to_ext.get(mime_type)
    except Exception as e:
        # Use logger if app context is available, otherwise print
        logger = current_app.logger if current_app else print
        logger(f"Error validating image: {e}", exc_info=True)
        return None

def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def save_file(file):
    """Save file with security checks"""
    if not file or not file.filename: return None
    if not allowed_file(file.filename):
        flash(f"File extension not allowed. Allowed: {', '.join(ALLOWED_EXTENSIONS)}", "warning")
        return None

    img_ext = validate_image(file.stream) # Use file.stream
    if not img_ext:
         flash(f"File content does not appear to be a valid image.", "warning")
         return None

    try:
        filename = secure_filename(str(uuid4()) + img_ext)
        file_path = os.path.join(UPLOAD_FOLDER, filename)
        file.save(file_path)
        return filename
    except Exception as e:
        logger = current_app.logger if current_app else print
        logger(f"Error saving file {file.filename}: {e}", exc_info=True)
        flash("An error occurred while saving the uploaded file.", "error")
        return None

# --- Decorators ---

def buyer_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('user_login'))

        buyer = db_session.query(Buyer).filter_by(user_id=current_user.id).first()
        required_challenges = 3 # Configurable?

        if not buyer:
            flash('Create a buyer profile and complete challenges to access the marketplace.', 'info')
            return redirect(url_for('marketplace.buyer_verification'))

        # Use actual verification logic (e.g., check solved challenges count)
        # Assuming Buyer model has 'solved_challenges' list/JSON field
        solved_count = len(buyer.solved_challenges or [])
        if solved_count < required_challenges:
             flash(f'You need to complete at least {required_challenges} easy challenges to access this page.', 'warning')
             return redirect(url_for('marketplace.buyer_verification'))

        # Add check for email verification IF it was still a requirement
        # if not current_user.email_verified:
        #     flash('Please verify your email address.', 'warning')
        #     return redirect(url_for('profile.index')) # Or wherever verification request is handled

        return f(*args, **kwargs)
    return decorated_function

def seller_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            flash('Please log in first.', 'warning')
            return redirect(url_for('auth.login'))  # or whatever your login route is

        seller = db_session.query(Seller).filter_by(user_id=current_user.username).first()
        
        if not seller:
            flash('Seller profile not found. Please register as a seller first.', 'danger')
            return redirect(url_for('marketplace.become_seller'))  # redirect to safe route

        if len(seller.get_solved_challenges()) < 5:
            flash(f'You need {5 - len(seller.get_solved_challenges())} more hard challenges to sell.', 'warning')
            return redirect(url_for('marketplace.seller_verification'))

        return f(*args, **kwargs, seller=seller)  # optional: pass seller to view
    return decorated_function


# --- NOW Define Routes using the Blueprint ---

@marketplace_bp.route('/')
def index():
    """Marketplace landing page - shows products if buyer is verified."""
    products = []
    buyer = None
    if current_user.is_authenticated:
        buyer = db_session.query(Buyer).filter_by(user_id=current_user.id).first()
        required_challenges = 3
        solved_count = len(buyer.solved_challenges or []) if buyer else 0
        # Check verification status (challenges completed, potentially other checks later)
        if buyer and solved_count >= required_challenges:
            products = db_session.query(Product).filter_by(is_active=True).order_by(Product.created_at.desc()).all()
            return render_template('marketplace/index.html', products=products, buyer=buyer)

    return render_template('marketplace/welcome.html')


@marketplace_bp.route('/buyer/verify')
@login_required
def buyer_verification():
    """Page for buyers to see challenge status for verification."""
    buyer = db_session.query(Buyer).filter_by(user_id=current_user.id).first()
    required_count = 3

    if buyer and len(buyer.solved_challenges or []) >= required_count:
        flash('You are already a verified buyer!', 'success')
        return redirect(url_for('marketplace.view_products'))

    try:
        all_challenges = challenge_manager.get_all_challenges()
        easy_challenges = {k: v for k, v in all_challenges.items() if v.get('difficulty') == 'easy'}
    except Exception as e:
        current_app.logger.error(f"Failed to get challenges for buyer verification: {e}", exc_info=True)
        flash("Could not load challenges. Please try again later.", "error")
        easy_challenges = {}

    solved_challenge_ids = set(buyer.solved_challenges if buyer and buyer.solved_challenges else [])
    solved_easy_count = sum(1 for c_id in easy_challenges if c_id in solved_challenge_ids)

    return render_template('marketplace/buyer_verification.html',
                           easy_challenges=easy_challenges,
                           solved_challenge_ids=solved_challenge_ids,
                           solved_easy_count=solved_easy_count,
                           required_count=required_count,
                           buyer=buyer)


@marketplace_bp.route('/products')
@login_required
@buyer_required # Handles verification checks
def view_products():
    """View all products (requires buyer verification)"""
    products = db_session.query(Product).filter_by(is_active=True).order_by(Product.created_at.desc()).all()
    return render_template('marketplace/products.html', products=products)


@marketplace_bp.route("/seller/register", methods=["GET", "POST"])
def seller_register():
    """Register a NEW user AS a seller (creates User and Seller)."""
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        email = request.form.get("email")
        business_name = request.form.get("business_name")
        description = request.form.get("description")

        if not all([username, password, email, business_name]):
            flash("Username, password, email, and business name are required.", "error")
            return render_template("marketplace/seller_register.html")

        if db_session.query(User).filter_by(username=username).first():
            flash("Username already exists", "error")
            return render_template("marketplace/seller_register.html")
        if db_session.query(User).filter_by(email=email).first():
            flash("Email already registered", "error")
            return render_template("marketplace/seller_register.html")

        user = User(
            username=username,
            password_hash=generate_password_hash(password),
            email=email,
            email_verified=True, # Assume verified since we removed the process
            is_active=True,
            is_admin=False
            # created_at=datetime.utcnow() # If applicable
        )
        db_session.add(user)
        try:
             db_session.flush()
        except Exception as e:
             db_session.rollback()
             current_app.logger.error(f"Seller registration flush error for user '{username}': {e}", exc_info=True)
             flash("Registration failed during user creation. Please try again.", "error")
             return render_template("marketplace/seller_register.html")

        seller = Seller(
            user_id=user.id, # Link to user's primary key
            business_name=business_name,
            description=description,
            is_verified=0 # Needs challenge verification
        )
        db_session.add(seller)

        try:
            db_session.commit()
            login_user(user)
            # Removed email sending
            flash("Registration successful!", "success")
            return redirect(url_for("marketplace.seller_verification"))
        except Exception as e:
            db_session.rollback()
            print(f"Seller Registration failed for user '{username}'. Error: {e}")
            print(traceback.format_exc())
            current_app.logger.error(f"Seller Registration failed for user '{username}': {e}", exc_info=True)
            flash("Registration failed. Please try again.", "error")
            return render_template("marketplace/seller_register.html")

    return render_template("marketplace/seller_register.html")


@marketplace_bp.route("/buyer/register", methods=["GET", "POST"])
def buyer_register():
    """Register a NEW user AS a buyer (creates User and Buyer)."""
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        email = request.form.get("email")
        display_name = request.form.get("display_name")

        if not all([username, password, email, display_name]):
             flash("Username, password, email, and display name are required.", "error")
             return render_template("marketplace/buyer_register.html")

        if db_session.query(User).filter_by(username=username).first():
            flash("Username already exists", "error")
            return render_template("marketplace/buyer_register.html")
        if db_session.query(User).filter_by(email=email).first():
            flash("Email already registered", "error")
            return render_template("marketplace/buyer_register.html")

        user = User(
            username=username,
            password_hash=generate_password_hash(password),
            email=email,
            email_verified=True, # Assume verified
            is_active=True,
            is_admin=False
            # created_at=datetime.utcnow() # If applicable
        )
        db_session.add(user)
        try:
             db_session.flush()
        except Exception as e:
             db_session.rollback()
             current_app.logger.error(f"Buyer registration flush error for user '{username}': {e}", exc_info=True)
             flash("Registration failed during user creation. Please try again.", "error")
             return render_template("marketplace/buyer_register.html")

        buyer = Buyer(
            user_id=user.id, # Link to user's primary key
            display_name=display_name,
            is_verified=0 # Needs challenge verification
        )
        db_session.add(buyer)

        try:
            db_session.commit()
            login_user(user)
            # Removed email sending
            flash("Registration successful!", "success")
            return redirect(url_for("marketplace.buyer_verification"))
        except Exception as e:
            db_session.rollback()
            print(f"Buyer Registration failed for user '{username}'. Error: {e}")
            print(traceback.format_exc())
            current_app.logger.error(f"Buyer Registration failed for user '{username}': {e}", exc_info=True)
            flash("Registration failed. Please try again.", "error")
            return render_template("marketplace/buyer_register.html")

    return render_template("marketplace/buyer_register.html")


# --- This route seems redundant? ---
# Renaming endpoint slightly to avoid clash if needed
# Use this if a LOGGED IN user wants to ADD a seller profile
@marketplace_bp.route('/become-seller', methods=['GET', 'POST'])
@login_required
def become_seller():
    """Allow logged-in user to register as a seller (creates Seller profile only)."""
    if db_session.query(Seller).filter_by(user_id=current_user.id).first():
        flash('You are already registered as a seller.', 'info')
        return redirect(url_for('marketplace.seller_verification'))

    if request.method == 'POST':
        business_name = request.form.get('business_name')
        description = request.form.get('description')

        if not business_name:
            flash('Business name is required.', 'error')
            # Re-render the same form on error
            return render_template('marketplace/become_seller_form.html')

        seller = Seller(
            user_id=current_user.id,
            business_name=business_name,
            description=description,
            is_verified=0
        )
        try:
            db_session.add(seller)
            db_session.commit()
            flash('Successfully registered as a seller. Complete 5 hard challenges to start selling!', 'success')
            return redirect(url_for('marketplace.seller_verification'))
        except Exception as e:
            db_session.rollback()
            current_app.logger.error(f"Error registering existing user {current_user.id} as seller: {e}", exc_info=True)
            flash("Failed to register as seller. Please try again.", "error")

    # Show form for existing user to add seller details
    return render_template('marketplace/become_seller_form.html') # Needs this template


@marketplace_bp.route('/seller/verification')
@login_required
def seller_verification():
    """Page for sellers to see challenge status for verification."""
    seller = db_session.query(Seller).filter_by(user_id=current_user.id).first()
    required_count = 5

    if seller and len(seller.solved_challenges or []) >= required_count:
        flash('You are already a verified seller!', 'success')
        return redirect(url_for('marketplace.seller_products'))

    try:
        all_challenges = challenge_manager.get_all_challenges()
        hard_challenges = {k: v for k, v in all_challenges.items() if v.get('difficulty') == 'hard'}
    except Exception as e:
        current_app.logger.error(f"Failed to get challenges for seller verification: {e}", exc_info=True)
        flash("Could not load challenges. Please try again later.", "error")
        hard_challenges = {}

    solved_challenge_ids = set(seller.solved_challenges if seller and seller.solved_challenges else [])
    solved_hard_count = sum(1 for c_id in hard_challenges if c_id in solved_challenge_ids)

    return render_template('marketplace/seller_verification.html',
                           hard_challenges=hard_challenges,
                           solved_challenge_ids=solved_challenge_ids,
                           solved_hard_count=solved_hard_count,
                           required_count=required_count,
                           seller=seller)


@marketplace_bp.route('/products/new', methods=['GET', 'POST'])
@login_required
@seller_required
def create_product():
    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description', '')
        price = float(request.form.get('price', 0))
        stock = int(request.form.get('stock', 0))
        category = request.form.get('category') or 'Other'

        # Image upload
        image_filename = None
        if 'image' in request.files:
            file = request.files['image']
            if file and file.filename:
                image_filename = save_file(file)

        # ←←← THIS WAS THE BUG ←←←
        seller = db_session.query(Seller).filter_by(user_id=current_user.username).first()

        if not seller:
            flash('Seller profile not found. Please contact admin.', 'error')
            return redirect(url_for('marketplace.index'))

        product = Product(
            seller_id=seller.id,           # now safe because seller exists
            name=name,
            description=description,
            price=price,
            stock=stock,
            category=category,
            image_path=image_filename,
            is_active=True
        )
        db_session.add(product)
        db_session.commit()

        flash('Product created successfully!', 'success')
        return redirect(url_for('marketplace.seller_products'))

    return render_template('marketplace/create_product.html')

@marketplace_bp.route('/products/manage')
@login_required
@seller_required
def seller_products():
    """List all products for the current seller"""
    seller = db_session.query(Seller).filter_by(user_id=current_user.id).first()
    products = db_session.query(Product).filter_by(seller_id=seller.id).order_by(Product.created_at.desc()).all()
    return render_template('marketplace/seller_products.html', products=products)


@marketplace_bp.route('/products/<int:product_id>/edit', methods=['GET', 'POST'])
@login_required
@seller_required
def edit_product(product_id):
    """Edit a product listing"""
    seller = db_session.query(Seller).filter_by(user_id=current_user.id).first()
    product = db_session.query(Product).filter_by(id=product_id, seller_id=seller.id).first()
    if not product: abort(404, description="Product not found or permission denied.")

    if request.method == 'POST':
        name = request.form.get('name')
        price_str = request.form.get('price')
        stock_str = request.form.get('stock')
        if not name or not price_str or not stock_str:
             flash('Name, price, and stock are required.', 'error')
             return render_template('marketplace/edit_product.html', product=product)
        try:
            price = float(price_str); stock = int(stock_str)
            if price <= 0 or stock < 0: raise ValueError("Invalid price/stock.")
        except ValueError:
             flash('Invalid price or stock value.', 'error')
             return render_template('marketplace/edit_product.html', product=product)

        product.name = name
        product.description = request.form.get('description')
        product.price = price
        product.stock = stock
        product.category = request.form.get('category')
        product.is_active = request.form.get('is_active') == 'on'

        if 'image' in request.files:
            file = request.files['image']
            if file and file.filename:
                image_filename = save_file(file)
                if not image_filename: return render_template('marketplace/edit_product.html', product=product)
                # Delete old image
                if product.image_filename:
                    try:
                        old_image_path = os.path.join(UPLOAD_FOLDER, product.image_filename)
                        if os.path.exists(old_image_path): os.remove(old_image_path)
                    except OSError as rm_error: logger.warning(f"Could not remove old image {product.image_filename}: {rm_error}")
                product.image_filename = image_filename

        try:
            db_session.commit()
            flash('Product updated successfully!', 'success')
            return redirect(url_for('marketplace.seller_products'))
        except Exception as e:
            db_session.rollback()
            current_app.logger.error(f"Error editing product {product_id}: {e}", exc_info=True)
            flash("Failed to update product. Please try again.", "error")

    return render_template('marketplace/edit_product.html', product=product)


@marketplace_bp.route('/products/<int:product_id>/delete', methods=['POST'])
@login_required
@seller_required
def delete_product(product_id):
    """Delete a product listing"""
    seller = db_session.query(Seller).filter_by(user_id=current_user.id).first()
    product = db_session.query(Product).filter_by(id=product_id, seller_id=seller.id).first()
    if not product:
         flash('Product not found or you do not have permission.', 'error')
         return redirect(url_for('marketplace.seller_products'))

    image_to_delete = product.image_filename
    try:
        db_session.delete(product)
        db_session.commit()
        flash('Product deleted successfully!', 'success')
        # Try removing image file
        if image_to_delete:
            try:
                image_path = os.path.join(UPLOAD_FOLDER, image_to_delete)
                if os.path.exists(image_path): os.remove(image_path)
            except OSError as rm_error: current_app.logger.warning(f"Could not remove image file {image_to_delete}: {rm_error}")
    except Exception as e:
        db_session.rollback()
        current_app.logger.error(f"Error deleting product {product_id}: {e}", exc_info=True)
        flash('Failed to delete product. Please try again.', 'error')

    return redirect(url_for('marketplace.seller_products'))


@marketplace_bp.route('/uploads/products/<path:filename>')
def product_image(filename):
    """Serve product images"""
    if '..' in filename or filename.startswith('/'): abort(400)
    try:
        # Ensure UPLOAD_FOLDER is absolute for send_from_directory
        safe_upload_folder = os.path.abspath(UPLOAD_FOLDER)
        return send_from_directory(safe_upload_folder, filename)
    except FileNotFoundError:
         abort(404)


# --- Placeholder routes for checkout/payment ---
# --- Need significant implementation ---

@marketplace_bp.route('/checkout/<int:product_id>', methods=['GET', 'POST'])
@login_required
@buyer_required
def checkout(product_id):
    """Handle product checkout - Placeholder"""
    buyer = db_session.query(Buyer).filter_by(user_id=current_user.id).first()
    product = db_session.query(Product).get(product_id)

    if not product or not product.is_active:
        flash("Product not found or is no longer available.", "error"); return redirect(url_for('marketplace.view_products'))
    if product.stock <= 0:
         flash("Sorry, this product is out of stock.", "warning"); return redirect(url_for('marketplace.view_products'))

    if request.method == 'GET':
        payment_methods = [] # TODO: Fetch from Stripe via helper
        if not payment_methods: flash("Please add a payment method.", "warning") # Redirect?
        return render_template('marketplace/checkout.html', product=product, payment_methods=payment_methods, stripe_public_key=os.getenv('STRIPE_PUBLIC_KEY'))
    else: # POST
        payment_method_id = request.form.get('payment_method_id') # This might be Stripe PM ID
        if not payment_method_id:
             flash("Please select a payment method.", "error")
             return render_template('marketplace/checkout.html', product=product, payment_methods=[], stripe_public_key=os.getenv('STRIPE_PUBLIC_KEY'))

        # TODO: process_payment(buyer, product, payment_method_id)
        success, message = False, "Payment processing not implemented."

        if success:
            flash("Purchase successful!", "success"); return redirect(url_for('marketplace.order_confirmation', payment_id=0)) # Pass real payment ID
        else:
            flash(f"Purchase failed: {message}", "error")
            return render_template('marketplace/checkout.html', product=product, payment_methods=[], stripe_public_key=os.getenv('STRIPE_PUBLIC_KEY'))


@marketplace_bp.route('/payment/<int:payment_id>/confirmation')
@login_required
def order_confirmation(payment_id):
    """Show order confirmation page - Placeholder"""
    payment = db_session.query(Payment).join(Buyer).filter(Payment.id == payment_id, Buyer.user_id == current_user.id).first()
    if not payment: abort(404, description="Order not found or permission denied.")
    return render_template('marketplace/confirmation.html', payment=payment)


# --- Routes for Managing Payment Methods (Placeholders) ---

@marketplace_bp.route('/payment-methods', methods=['GET'])
@login_required
@buyer_required
def payment_methods():
    """View and manage payment methods - Placeholder"""
    payment_methods_list = [] # TODO: Fetch from Stripe via helper
    return render_template('marketplace/payment_methods.html', payment_methods=payment_methods_list, stripe_public_key=os.getenv('STRIPE_PUBLIC_KEY'))


@marketplace_bp.route('/payment-methods/add', methods=['POST'])
@login_required
@buyer_required
def add_payment_method():
    """Add a new payment method - Placeholder"""
    stripe_payment_method_id = request.form.get('stripe_payment_method_id')
    if not stripe_payment_method_id:
         flash("Failed to get payment method details from Stripe.", "error")
         return redirect(url_for('marketplace.payment_methods'))
    buyer = db_session.query(Buyer).filter_by(user_id=current_user.id).first()
    try:
        # TODO: Implement Stripe customer creation/attachment logic
        flash("Payment method added successfully (Placeholder).", "success")
    except Exception as e:
        current_app.logger.error(f"Error adding payment method for user {current_user.id}: {e}", exc_info=True)
        flash(f"Error adding payment method: {str(e)}", "error")
    return redirect(url_for('marketplace.payment_methods'))


@marketplace_bp.route('/payment-methods/delete', methods=['POST'])
@login_required
@buyer_required
def delete_payment_method():
    """Delete a payment method - Placeholder"""
    stripe_payment_method_id = request.form.get('stripe_payment_method_id')
    if not stripe_payment_method_id:
        flash("No payment method specified for deletion.", "error")
        return redirect(url_for('marketplace.payment_methods'))
    try:
        # TODO: Implement Stripe detach logic
        success = True # Placeholder
        if success: flash("Payment method detached successfully (Placeholder).", "success")
        else: flash("Failed to detach payment method via Stripe (Placeholder).", "error")
    except Exception as e:
        current_app.logger.error(f"Error deleting payment method {stripe_payment_method_id} for user {current_user.id}: {e}", exc_info=True)
        flash(f"Error deleting payment method: {str(e)}", "error")
    return redirect(url_for('marketplace.payment_methods'))
