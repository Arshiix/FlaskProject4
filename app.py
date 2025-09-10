import os
import re
from werkzeug.utils import secure_filename
from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_admin import Admin
from flask import send_from_directory
from flask_admin.contrib.sqla import ModelView
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect, CSRFError
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired
from flask_mail import Mail, Message
from sqlalchemy.sql import func
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4
from PIL import Image as PILImage
import time
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime

# =======================
# App & Config
# =======================
app = Flask(__name__)

# -----------------------
# Environment Variables with Validation
# -----------------------
def validate_env_vars():
    required_vars = [
        'SECRET_KEY',
        'DATABASE_URI',
        'MAIL_SERVER',
        'MAIL_PORT',
        'MAIL_USERNAME',
        'MAIL_PASSWORD',
        'MAIL_DEFAULT_SENDER'
    ]
    for var in required_vars:
        if not os.getenv(var):
            raise EnvironmentError(f"Missing required environment variable: {var}")

validate_env_vars()

app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URI')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/images'
os.makedirs(os.path.join(app.config['UPLOAD_FOLDER'], 'user_uploads'), exist_ok=True)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max upload

# -----------------------
# Email Configuration
# -----------------------
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT'))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS', 'False').lower() == 'true'
app.config['MAIL_USE_SSL'] = os.getenv('MAIL_USE_SSL', 'False').lower() == 'true'
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER')

# -----------------------
# Session Security
# -----------------------
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,  # Requires HTTPS in production
    SESSION_COOKIE_SAMESITE='Lax',
    REMEMBER_COOKIE_HTTPONLY=True,
    REMEMBER_COOKIE_DURATION=3600,  # 1 hour
    PERMANENT_SESSION_LIFETIME=3600
)

# =======================
# Logging
# =======================
os.makedirs('logs', exist_ok=True)
handler = RotatingFileHandler('logs/adora.log', maxBytes=1_000_000, backupCount=5)
handler.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
app.logger.addHandler(handler)
app.logger.setLevel(logging.INFO)

# =======================
# Extensions
# =======================
mail = Mail(app)
db = SQLAlchemy(app)
csrf = CSRFProtect(app)
admin = Admin(app, name='Adora Admin', template_mode='bootstrap4')
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Rate Limiting for Login
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# =======================
# Password Validation
# =======================
def is_strong_password(password):
    if len(password) < 12:
        return False, "Password must be at least 12 characters long."
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter."
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter."
    if not re.search(r"[0-9]", password):
        return False, "Password must contain at least one digit."
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False, "Password must contain at least one special character."
    return True, "Password is valid."

# =======================
# Error Handling for CSRF
# =======================
@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    app.logger.error(f"CSRF error: {str(e)}")
    flash('CSRF token is missing or invalid. Please try again.', 'danger')
    return redirect(url_for('login'))

# =======================
# Initialize Database Function
# =======================
def init_db():
    with app.app_context():
        db.create_all()
        if not User.query.first():
            default_password = os.getenv('ADMIN_DEFAULT_PASSWORD')
            is_valid, message = is_strong_password(default_password)
            if not is_valid:
                raise ValueError(f"Default admin password is not secure: {message}")
            hashed_pw = generate_password_hash(default_password, method='pbkdf2:sha256:600000')
            db.session.add(User(username='admin', password=hashed_pw))
            app.logger.info("Created default admin user")

        global categories
        existing_categories = set(categories)
        for service in Service.query.all():
            category = service.name.lower().replace(' ', '_')
            if category not in existing_categories:
                categories.append(category)
                os.makedirs(os.path.join(app.config['UPLOAD_FOLDER'], category), exist_ok=True)
        if not Testimonial.query.first():
            testimonials_data = [
                {'client_name': 'Sarah L.', 'content': 'Adora transformed our Uxbridge kitchen with precision.', 'location': 'Uxbridge', 'rating': 5, 'is_user_submitted': False},
                {'client_name': 'James P.', 'content': 'Professional bathroom renovation in Pinner. Highly recommended.', 'location': 'Pinner', 'rating': 4, 'is_user_submitted': False},
                {'client_name': 'Emma R.', 'content': 'Bespoke wardrobe in Ickenham was perfect.', 'location': 'Ickenham', 'rating': 5, 'is_user_submitted': False}
            ]
            for data in testimonials_data:
                db.session.add(Testimonial(**data))
        if not Tip.query.first():
            tips_data = [
                {'title': 'Choosing Durable Flooring', 'content': 'Porcelain tiles are ideal for Ruislip’s damp climate.'},
                {'title': 'Maximizing Kitchen Space', 'content': 'Use pull-out cabinets for efficient Uxbridge kitchens.'},
                {'title': 'Eco-Friendly Plumbing', 'content': 'Low-flow taps save water in Ealing homes.'}
            ]
            for data in tips_data:
                db.session.add(Tip(**data))
        db.session.commit()
        app.logger.info("Database initialized successfully")

# =======================
# Categories
# =======================
categories = []
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
for cat in categories:
    os.makedirs(os.path.join(app.config['UPLOAD_FOLDER'], cat), exist_ok=True)

# =======================
# Models
# =======================
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(256), nullable=False)

class Service(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    description = db.Column(db.Text, nullable=False)
    images = db.relationship('Image', backref='service', lazy=True)

class Image(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(200), nullable=False)
    category = db.Column(db.String(100), nullable=False)
    service_id = db.Column(db.Integer, db.ForeignKey('service.id'))

class Testimonial(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    client_name = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    location = db.Column(db.String(100), nullable=True)
    rating = db.Column(db.Integer, nullable=True)
    is_user_submitted = db.Column(db.Boolean, default=False, nullable=False)

class Tip(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)

# =======================
# Initialize Database
# =======================
init_db()

# =======================
# Admin Views
# =======================
class SecureModelView(ModelView):
    def is_accessible(self):
        return current_user.is_authenticated

class TestimonialModelView(SecureModelView):
    column_list = ['id', 'client_name', 'content', 'location', 'rating', 'is_user_submitted']
    column_filters = ['client_name', 'location', 'is_user_submitted']
    column_searchable_list = ['client_name', 'content', 'location']
    form_columns = ['client_name', 'content', 'location', 'rating', 'is_user_submitted']

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

admin.add_view(SecureModelView(User, db.session))
admin.add_view(SecureModelView(Service, db.session))
admin.add_view(SecureModelView(Image, db.session))
admin.add_view(TestimonialModelView(Testimonial, db.session))
admin.add_view(SecureModelView(Tip, db.session))

# =======================
# Login Manager
# =======================
@login_manager.user_loader
def load_user(user_id):
    user = User.query.get(int(user_id))
    app.logger.info(f"Loading user: {user_id}, found: {user}")
    return user

# =======================
# Allowed File Extensions
# =======================
ALLOWED_EXTENSIONS = {'.png', '.jpg', '.jpeg'}

def is_allowed_file(filename):
    return os.path.splitext(filename)[1].lower() in ALLOWED_EXTENSIONS

# =======================
# Routes
# =======================
@app.route('/reset_admin')
def reset_admin():
    with app.app_context():
        user = User.query.filter_by(username='admin').first()
        if not user:
            default_password = os.getenv('ADMIN_DEFAULT_PASSWORD')
            is_valid, message = is_strong_password(default_password)
            if not is_valid:
                return jsonify({'error': message})
            hashed_pw = generate_password_hash(default_password, method='pbkdf2:sha256:600000')
            db.session.add(User(username='admin', password=hashed_pw))
            db.session.commit()
            app.logger.info("Admin user created")
            return jsonify({'status': 'Admin user created'})
        else:
            default_password = os.getenv('ADMIN_DEFAULT_PASSWORD')
            hashed_pw = generate_password_hash(default_password, method='pbkdf2:sha256:600000')
            user.password = hashed_pw
            db.session.commit()
            app.logger.info("Admin user password reset")
            return jsonify({'status': 'Admin user password reset'})

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        user = User.query.filter_by(username=username).first()
        app.logger.info(f"Login attempt: {username}, user_exists: {user is not None}, password_match: {user and check_password_hash(user.password, password)}")
        if user and check_password_hash(user.password, password):
            login_user(user)
            app.logger.info(f"Successful login for user: {username}")
            flash('Logged in successfully.', 'success')
            return redirect(url_for('admin_dashboard'))
    return render_template('login.html', form=form)



@app.route('/sitemap.xml')
def sitemap():
    return send_from_directory('static', 'sitemap.xml')

@app.route('/logout')
@login_required
def logout():
    app.logger.info(f"User {current_user.username} logged out")
    logout_user()
    flash('Logged out successfully.', 'success')
    return redirect(url_for('index'))

@app.route('/admin/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if not check_password_hash(current_user.password, current_password):
            app.logger.warning(f"Password change failed for {current_user.username}: Incorrect current password")
            flash('Current password is incorrect.', 'danger')
            return redirect(url_for('change_password'))

        if new_password != confirm_password:
            app.logger.warning(f"Password change failed for {current_user.username}: Passwords do not match")
            flash('New passwords do not match.', 'danger')
            return redirect(url_for('change_password'))

        is_valid, message = is_strong_password(new_password)
        if not is_valid:
            app.logger.warning(f"Password change failed for {current_user.username}: {message}")
            flash(message, 'danger')
            return redirect(url_for('change_password'))

        current_user.password = generate_password_hash(new_password, method='pbkdf2:sha256:600000')
        db.session.commit()
        app.logger.info(f"Password changed successfully for user: {current_user.username}")
        flash('Password changed successfully.', 'success')
        return redirect(url_for('admin_dashboard'))

    return render_template('change_password.html')

@app.route('/admin')
@login_required
def admin_dashboard():
    services = Service.query.all()
    testimonials = Testimonial.query.all()
    tips = Tip.query.all()
    images = Image.query.all()
    return render_template('admin_dashboard.html', services=services, testimonials=testimonials, tips=tips, images=images)

@app.route('/admin/add_service', methods=['GET', 'POST'])
@login_required
@csrf.exempt
def add_service():
    if request.method == 'POST':
        name = request.form.get('name').strip().title()
        description = request.form.get('description')
        if name and description:
            new_service = Service(name=name, description=description)
            db.session.add(new_service)
            db.session.commit()
            new_category = name.lower().replace(" ", "_")
            if new_category not in categories:
                categories.append(new_category)
                os.makedirs(os.path.join(app.config['UPLOAD_FOLDER'], new_category), exist_ok=True)
            flash('Service added successfully.', 'success')
            app.logger.info(f"Service added: {name} by user {current_user.username}")
            return redirect(url_for('admin_dashboard'))
        flash('Please fill in all fields.', 'danger')
    return render_template('add_service.html')

@app.route('/admin/add_testimonial', methods=['GET', 'POST'])
@login_required
@csrf.exempt
def add_testimonial():
    if request.method == 'POST':
        client_name = request.form.get('client_name')
        content = request.form.get('content')
        location = request.form.get('location')
        rating = request.form.get('rating')
        is_user_submitted = request.form.get('is_user_submitted') == 'on'
        if client_name and content and rating:
            new_testimonial = Testimonial(client_name=client_name, content=content, location=location, rating=int(rating), is_user_submitted=is_user_submitted)
            db.session.add(new_testimonial)
            db.session.commit()
            app.logger.info(f"Testimonial added by user {current_user.username}")
            flash('Testimonial added successfully.', 'success')
            return redirect(url_for('admin_dashboard'))
        flash('Please fill in all required fields.', 'danger')
    return render_template('add_testimonial.html')

@app.route('/admin/add_tip', methods=['GET', 'POST'])
@login_required
@csrf.exempt
def add_tip():
    if request.method == 'POST':
        title = request.form.get('title')
        content = request.form.get('content')
        if title and content:
            new_tip = Tip(title=title, content=content)
            db.session.add(new_tip)
            db.session.commit()
            app.logger.info(f"Tip added by user {current_user.username}")
            flash('Tip added successfully.', 'success')
            return redirect(url_for('admin_dashboard'))
        flash('Please fill in all fields.', 'danger')
    return render_template('add_tip.html')

@app.route('/upload', methods=['GET', 'POST'])
@login_required
@csrf.exempt
def upload():
    if request.method == 'POST':
        files = request.files.getlist('files')
        category = request.form.get('category')
        if not files or not category or category not in categories:
            flash('Select files and a valid category.', 'danger')
            return redirect(request.url)
        for file in files:
            if file and file.filename.lower().endswith(('.png', '.jpg', '.jpeg')):
                filename = secure_filename(file.filename)
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], category, filename)
                file.save(file_path)
                if os.path.exists(file_path):
                    service = Service.query.filter(Service.name.ilike(category.replace('_', ' ').title())).first()
                    app.logger.info(f"Upload: Category={category}, Service={service.name if service else 'None'}, Filename={filename} by user {current_user.username}")
                    new_image = Image(filename=filename, category=category, service_id=service.id if service else None)
                    db.session.add(new_image)
                else:
                    flash(f'Failed to save file: {file.filename}', 'warning')
                    app.logger.error(f"Failed to save file: {file_path}")
        db.session.commit()
        flash('Images uploaded successfully.', 'success')
        return redirect(url_for('admin_dashboard'))
    return render_template('upload.html', categories=categories)

@app.route('/admin/service/<int:id>/edit', methods=['GET', 'POST'])
@login_required
@csrf.exempt
def edit_service(id):
    service = Service.query.get_or_404(id)
    if request.method == 'POST':
        service.name = request.form.get('name')
        service.description = request.form.get('description')
        if service.name and service.description:
            db.session.commit()
            app.logger.info(f"Service {service.name} updated by user {current_user.username}")
            flash('Service updated successfully.', 'success')
            return redirect(url_for('admin_dashboard'))
        flash('Please fill in all fields.', 'danger')
    return render_template('edit_service.html', service=service)

@app.route('/admin/service/<int:id>/delete', methods=['POST'])
@login_required
@csrf.exempt
def delete_service(id):
    service = Service.query.get_or_404(id)
    db.session.delete(service)
    db.session.commit()
    app.logger.info(f"Service {id} deleted by user {current_user.username}")
    flash('Service deleted successfully.', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/testimonial/<int:id>/edit', methods=['GET', 'POST'])
@login_required
@csrf.exempt
def edit_testimonial(id):
    testimonial = Testimonial.query.get_or_404(id)
    if request.method == 'POST':
        testimonial.client_name = request.form.get('client_name')
        testimonial.content = request.form.get('content')
        testimonial.location = request.form.get('location')
        testimonial.rating = request.form.get('rating')
        testimonial.is_user_submitted = request.form.get('is_user_submitted') == 'on'
        if testimonial.client_name and testimonial.content and testimonial.rating:
            db.session.commit()
            app.logger.info(f"Testimonial {id} updated by user {current_user.username}")
            flash('Testimonial updated successfully.', 'success')
            return redirect(url_for('admin_dashboard'))
        flash('Please fill in all required fields.', 'danger')
    return render_template('edit_testimonial.html', testimonial=testimonial)

@app.route('/admin/testimonial/<int:id>/delete', methods=['POST'])
@login_required
@csrf.exempt
def delete_testimonial(id):
    testimonial = Testimonial.query.get_or_404(id)
    db.session.delete(testimonial)
    db.session.commit()
    app.logger.info(f"Testimonial {id} deleted by user {current_user.username}")
    flash('Testimonial deleted successfully.', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/tip/<int:id>/edit', methods=['GET', 'POST'])
@login_required
@csrf.exempt
def edit_tip(id):
    tip = Tip.query.get_or_404(id)
    if request.method == 'POST':
        tip.title = request.form.get('title')
        tip.content = request.form.get('content')
        if tip.title and tip.content:
            db.session.commit()
            app.logger.info(f"Tip {id} updated by user {current_user.username}")
            flash('Tip updated successfully.', 'success')
            return redirect(url_for('admin_dashboard'))
        flash('Please fill in all fields.', 'danger')
    return render_template('edit_tip.html', tip=tip)

@app.route('/admin/tip/<int:id>/delete', methods=['POST'])
@login_required
@csrf.exempt
def delete_tip(id):
    tip = Tip.query.get_or_404(id)
    db.session.delete(tip)
    db.session.commit()
    app.logger.info(f"Tip {id} deleted by user {current_user.username}")
    flash('Tip deleted successfully.', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/image/<int:id>/edit', methods=['GET', 'POST'])
@login_required
@csrf.exempt
def edit_image(id):
    image = Image.query.get_or_404(id)
    if request.method == 'POST':
        image.category = request.form.get('category')
        service_name = request.form.get('service_name')
        service = Service.query.filter_by(name=service_name).first() if service_name else None
        image.service_id = service.id if service else None
        if image.category in categories:
            db.session.commit()
            app.logger.info(f"Image {id} updated by user {current_user.username}")
            flash('Image updated successfully.', 'success')
            return redirect(url_for('admin_dashboard'))
        flash('Please select a valid category.', 'danger')
    return render_template('edit_image.html', image=image, categories=categories, services=Service.query.all())

@app.route('/admin/image/<int:id>/delete', methods=['POST'])
@login_required
@csrf.exempt
def delete_image(id):
    image = Image.query.get_or_404(id)
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], image.category, image.filename)
    if os.path.exists(file_path):
        os.remove(file_path)
        app.logger.info(f"Image file {file_path} deleted by user {current_user.username}")
    db.session.delete(image)
    db.session.commit()
    app.logger.info(f"Image {id} deleted from database by user {current_user.username}")
    flash('Image deleted successfully.', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/')
def index():
    services = Service.query.all()
    testimonials = Testimonial.query.all()
    tips = Tip.query.order_by(Tip.id.desc()).limit(3).all()
    service_to_category = {
        'Kitchen Renovations': 'kitchen',
        'Bathroom Installations': 'bathroom',
        'Flooring Solutions': 'flooring',
        'Wardrobe Installations': 'wardrobe',
        'Plumbing Repairs': 'plumbing',
        'Carpentry & Tiling': 'carpentry_tiling',
        '3D Design Services': '3d_design'
    }
    gallery_data = {}
    for service in services:
        category = service_to_category.get(service.name, service.name.lower().replace(' ', '_'))
        images = Image.query.filter_by(category=category).all()
        app.logger.info(f"Service: {service.name}, Category: {category}, Images: {[img.filename for img in images]}")
        gallery_data[category] = images
    return render_template('index.html', services=services, testimonials=testimonials, tips=tips, gallery_data=gallery_data)

@app.route('/services')
def services():
    services = Service.query.all()
    service_to_category = {
        'Kitchen Renovations': 'kitchen',
        'Bathroom Installations': 'bathroom',
        'Flooring Solutions': 'flooring',
        'Wardrobe Installations': 'wardrobe',
        'Plumbing Repairs': 'plumbing',
        'Carpentry & Tiling': 'carpentry_tiling',
        '3D Design Services': '3d_design'
    }
    gallery_data = {service_to_category.get(service.name, service.name.lower().replace(' ', '_')): Image.query.filter_by(category=service_to_category.get(service.name, service.name.lower().replace(' ', '_'))).all() for service in services}
    return render_template('services.html', services=services, gallery_data=gallery_data)

@app.route('/service/<int:service_id>')
def service(service_id):
    service = Service.query.get_or_404(service_id)
    service_to_category = {
        'Kitchen Renovations': 'kitchen',
        'Bathroom Installations': 'bathroom',
        'Flooring Solutions': 'flooring',
        'Wardrobe Installations': 'wardrobe',
        'Plumbing Repairs': 'plumbing',
        'Carpentry & Tiling': 'carpentry_tiling',
        '3D Design Services': '3d_design'
    }
    category = service_to_category.get(service.name, service.name.lower().replace(' ', '_'))
    images = Image.query.filter_by(category=category).order_by(func.random()).limit(4).all()
    testimonials = Testimonial.query.all()
    tips = Tip.query.all()
    services = Service.query.all()
    filtered_testimonials = [
        t for t in testimonials
        if t.content and (
            service.name.lower() in t.content.lower() or
            (t.location and service.name.lower() in t.location.lower())
        )
    ]
    filtered_tips = [
        t for t in tips
        if t.content and (service.name.lower() in t.title.lower() or service.name.lower() in t.content.lower())
    ]
    return render_template(
        'service.html',
        service=service,
        images=images,
        testimonials=testimonials,
        filtered_testimonials=filtered_testimonials,
        tips=tips,
        filtered_tips=filtered_tips,
        services=services
    )

@app.route('/gallery')
def gallery():
    gallery_data = {cat: Image.query.filter_by(category=cat).all() for cat in categories}
    return render_template('gallery.html', gallery_data=gallery_data)

@app.route('/gallery/<category>')
def gallery_category(category):
    if category not in categories:
        flash("Category not found.", "danger")
        return redirect(url_for('gallery'))
    images = Image.query.filter_by(category=category).all()
    return render_template('gallery_category.html', category=category, images=images)

@app.route('/areas')
def areas():
    areas = ['Uxbridge', 'Pinner', 'Ruislip', 'Ickenham', 'Ealing', 'Acton', 'Richmond', 'Chiswick', 'Kensington', 'Chelsea']
    return render_template('areas.html', areas=areas)

@app.route('/contact', defaults={'service_id': None}, methods=['GET', 'POST'])
@app.route('/contact/<int:service_id>', methods=['GET', 'POST'])
@csrf.exempt
def contact(service_id):
    app.logger.info(f"Accessing /contact with service_id: {service_id}")
    service = Service.query.get(service_id) if service_id else None
    all_gallery_data = {}
    if not service:
        for cat in categories:
            all_gallery_data[cat] = Image.query.filter_by(category=cat).all()

    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip()
        message_body = request.form.get('message', '').strip()
        selected_images = request.form.get('selected_gallery_images', '').split(',') if request.form.get('selected_gallery_images') else []
        uploaded_files = request.files.getlist('uploaded_images')

        app.logger.info(f"Form data received: name={name}, email={email}, message={message_body}")
        app.logger.info(f"Selected gallery images: {selected_images}")
        app.logger.info(f"Uploaded files: {[f.filename for f in uploaded_files if f and f.filename]}")

        if not name or not email or not message_body:
            app.logger.error("Missing required fields: name, email, or message")
            flash('Please fill in all required fields (name, email, message).', 'danger')
            return redirect(url_for('contact', service_id=service_id))

        upload_dir = os.path.join(app.config['UPLOAD_FOLDER'], 'user_uploads')
        os.makedirs(upload_dir, exist_ok=True)
        app.logger.info(f"Upload directory ensured: {upload_dir}")

        saved_uploaded_files = []
        for file in uploaded_files:
            if file and file.filename:
                ext = os.path.splitext(file.filename)[1].lower()
                app.logger.info(f"Processing uploaded file: {file.filename}, ext: {ext}")
                if ext in ('.png', '.jpg', '.jpeg'):
                    filename = secure_filename(f"{int(time.time())}_{file.filename}")
                    filepath = os.path.join(upload_dir, filename)
                    try:
                        file.save(filepath)
                        if os.path.exists(filepath):
                            saved_uploaded_files.append((filepath, filename))
                            app.logger.info(f"Saved uploaded file: {filepath} (size: {os.path.getsize(filepath)} bytes)")
                        else:
                            app.logger.error(f"Failed to save file: {filepath}")
                            flash(f"Failed to save file: {file.filename}", 'warning')
                    except Exception as e:
                        app.logger.error(f"Error saving file {file.filename}: {str(e)}")
                        flash(f"Failed to save file {file.filename}: {str(e)}", 'warning')
                else:
                    app.logger.warning(f"Invalid file type for {file.filename}: {ext}")
                    flash(f"Invalid file type for {file.filename}. Only PNG, JPG, JPEG allowed.", 'warning')
            else:
                app.logger.warning("Received empty file in uploaded_files")

        saved_gallery_files = []
        for filename in selected_images:
            if not filename:
                app.logger.warning("Empty filename in selected_images")
                continue
            image = Image.query.filter_by(filename=filename).first()
            if image:
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], image.category, filename)
                if os.path.exists(filepath):
                    saved_gallery_files.append((filepath, filename))
                    app.logger.info(f"Found gallery image: {filepath} (size: {os.path.getsize(filepath)} bytes)")
                else:
                    app.logger.error(f"Gallery image not found on disk: {filepath}")
                    flash(f"Selected gallery image {filename} not found on disk.", 'warning')
            else:
                app.logger.error(f"Image {filename} not found in database")
                flash(f"Selected gallery image {filename} not found in database.", 'warning')

        app.logger.info(f"Saved uploaded files: {saved_uploaded_files}")
        app.logger.info(f"Saved gallery files: {saved_gallery_files}")

        timestamp = int(time.time())
        uploaded_pdf_path = os.path.join(upload_dir, f'uploaded_images_{name}_{timestamp}.pdf')
        gallery_pdf_path = os.path.join(upload_dir, f'gallery_images_{name}_{timestamp}.pdf')

        def create_pdf(file_list, pdf_path, title):
            if not file_list:
                app.logger.info(f"No files to create PDF: {title}")
                return None
            try:
                c = canvas.Canvas(pdf_path, pagesize=A4)
                c.setFont("Helvetica", 12)
                c.drawString(50, A4[1] - 50, title)
                y_position = A4[1] - 100
                for filepath, filename in file_list:
                    try:
                        img = PILImage.open(filepath)
                        img_width, img_height = img.size
                        aspect = img_height / float(img_width)
                        target_width = 500
                        target_height = target_width * aspect
                        if y_position - target_height < 50:
                            c.showPage()
                            c.setFont("Helvetica", 12)
                            y_position = A4[1] - 50
                        c.drawString(50, y_position, f"Image: {filename}")
                        c.drawImage(filepath, 50, y_position - target_height - 20, width=target_width, height=target_height)
                        y_position -= (target_height + 40)
                        app.logger.info(f"Added image to PDF: {filename}")
                    except Exception as e:
                        app.logger.error(f"Error adding image {filename} to PDF: {str(e)}")
                        flash(f"Failed to add image {filename} to PDF: {str(e)}", 'warning')
                c.save()
                if os.path.exists(pdf_path):
                    app.logger.info(f"Created PDF: {pdf_path} (size: {os.path.getsize(pdf_path)} bytes)")
                    return pdf_path
                else:
                    app.logger.error(f"PDF not created: {pdf_path}")
                    return None
            except Exception as e:
                app.logger.error(f"Error creating PDF {title}: {str(e)}")
                flash(f"Failed to create PDF {title}: {str(e)}", 'warning')
                return None

        uploaded_pdf = create_pdf(saved_uploaded_files, uploaded_pdf_path, "User Uploaded Images")
        gallery_pdf = create_pdf(saved_gallery_files, gallery_pdf_path, "Selected Gallery Images")

        try:
            msg = Message(f'Contact Form Submission: {name}', recipients=['adora.constructiontd@gmail.com'])
            msg.body = f"""
Name: {name}
Email: {email}
Message: {message_body}
Selected Gallery Images: {'Selected' if saved_gallery_files else 'None'}
Uploaded Images: {'Uploaded' if saved_uploaded_files else 'None'}
Service ID: {service_id if service_id else 'None'}
"""
            pdf_attachments = []
            if uploaded_pdf and os.path.exists(uploaded_pdf):
                pdf_attachments.append((uploaded_pdf, f'uploaded_images_{name}_{timestamp}.pdf'))
                app.logger.info(f"Prepared to attach uploaded PDF: {uploaded_pdf}")
            if gallery_pdf and os.path.exists(gallery_pdf):
                pdf_attachments.append((gallery_pdf, f'gallery_images_{name}_{timestamp}.pdf'))
                app.logger.info(f"Prepared to attach gallery PDF: {gallery_pdf}")

            for pdf_path, pdf_name in pdf_attachments:
                try:
                    with app.open_resource(pdf_path, 'rb') as fp:
                        msg.attach(pdf_name, 'application/pdf', fp.read())
                        app.logger.info(f"Attached PDF: {pdf_name} (size: {os.path.getsize(pdf_path)} bytes)")
                except Exception as e:
                    app.logger.error(f"Failed to attach PDF {pdf_name}: {str(e)}")
                    flash(f"Failed to attach PDF {pdf_name}: {str(e)}", 'warning')

            mail.send(msg)
            app.logger.info("Business email sent successfully")

            for filepath, _ in saved_uploaded_files:
                try:
                    if os.path.exists(filepath):
                        os.remove(filepath)
                        app.logger.info(f"Deleted temporary file: {filepath}")
                except Exception as e:
                    app.logger.error(f"Failed to delete file {filepath}: {str(e)}")
            for pdf_path, _ in pdf_attachments:
                try:
                    if os.path.exists(pdf_path):
                        os.remove(pdf_path)
                        app.logger.info(f"Deleted PDF: {pdf_path}")
                except Exception as e:
                    app.logger.error(f"Failed to delete PDF {pdf_path}: {str(e)}")

        except Exception as e:
            app.logger.error(f"Failed to send business email: {str(e)}")
            flash(f'Failed to send message: {str(e)}', 'danger')
            return redirect(url_for('contact', service_id=service_id))

        try:
            thank_you_msg = Message(
                subject="Thank you for contacting us!",
                recipients=[email]
            )
            thank_you_msg.body = f"""
Hi {name},

Thank you for reaching out to us. We have received your message and will get back to you as soon as possible.

Your message:
{message_body}

Best regards,
Adora Team
"""
            mail.send(thank_you_msg)
            app.logger.info("Customer confirmation email sent successfully")
        except Exception as e:
            app.logger.error(f"Failed to send customer email: {str(e)}")
            flash(f"Failed to send confirmation email: {str(e)}", 'warning')

        flash('Message sent successfully. A confirmation email has been sent to you.', 'success')
        return redirect(url_for('contact', service_id=service_id))

    return render_template('contact.html', service=service, gallery_images=service.images if service else [], all_gallery_data=all_gallery_data)

@app.route('/submit_review', methods=['POST'])
@csrf.exempt
def submit_review():
    if request.method == 'POST':
        client_name = request.form.get('client_name')
        content = request.form.get('content')
        location = request.form.get('location')
        rating = request.form.get('rating')
        if client_name and content and rating:
            try:
                new_review = Testimonial(
                    client_name=client_name,
                    content=content,
                    location=location,
                    rating=int(rating),
                    is_user_submitted=True
                )
                db.session.add(new_review)
                db.session.commit()
                app.logger.info(f"Review submitted by {client_name}")
                flash('Thank you for your review! It has been submitted successfully.', 'success')
            except Exception as e:
                app.logger.error(f"Failed to submit review: {str(e)}")
                flash('Failed to submit review. Please try again.', 'danger')
        else:
            flash('Please fill in all required fields (name, review, rating).', 'danger')
        return redirect(url_for('index'))
    return redirect(url_for('index'))

@app.route('/search_suggestions')
def search_suggestions():
    query = request.args.get('q', '')
    services = Service.query.filter(Service.name.ilike(f'%{query}%')).limit(5).all()
    suggestions = [service.name for service in services]
    return jsonify(suggestions)

@app.route('/static/<path:path>')
def serve_static(path):
    return send_from_directory('static', path)

@app.route('/about')
def about():
    return render_template('about.html')

# =======================
# Main
# =======================
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))  # Use Render's PORT env
    app.run(host="0.0.0.0", port=port)