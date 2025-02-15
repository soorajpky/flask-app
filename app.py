from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from forms import LoginForm, BoardForm, UserForm
from config import Config
import os
import uuid
from datetime import datetime

# Initialize app
app = Flask(__name__)
app.config.from_object(Config)

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Allowed image extensions
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

class Board(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    location_url = db.Column(db.String(300), nullable=False)
    renewal_date = db.Column(db.Date, nullable=False)
    renewal_amount = db.Column(db.Float, nullable=False)
    image = db.Column(db.String(300), nullable=True)
    updated_by = db.Column(db.String(150), nullable=True)
    updated_at = db.Column(db.DateTime, default=db.func.current_timestamp(), onupdate=db.func.current_timestamp())

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def home():
    return redirect(url_for('dashboard'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password', 'danger')
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    boards = Board.query.all()
    today = datetime.today().date()
    alert_boards = [board for board in boards if board.renewal_date and (0 <= (board.renewal_date - today).days <= 7)]
    return render_template('dashboard.html', boards=boards, alert_boards=alert_boards)

@app.route('/add_board', methods=['GET', 'POST'])
@login_required
def add_board():
    form = BoardForm()
    if form.validate_on_submit():
        image_filename = None
        if 'image' in request.files and request.files['image'].filename:
            image = request.files['image']
            if allowed_file(image.filename):
                filename = f"{uuid.uuid4()}_{secure_filename(image.filename)}"
                image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                image.save(image_path)
                image_filename = filename
            else:
                flash("Invalid file type! Please upload an image.", "danger")
                return redirect(request.url)

        new_board = Board(
            name=form.name.data,
            location_url=form.location_url.data,
            renewal_date=form.renewal_date.data,
            renewal_amount=form.renewal_amount.data,
            image=image_filename,
            updated_by=current_user.email
        )
        db.session.add(new_board)
        db.session.commit()
        flash('Board added successfully!', 'success')
        return redirect(url_for('dashboard'))
    return render_template('add_board.html', form=form)

@app.route('/edit_board/<int:board_id>', methods=['GET', 'POST'])
@login_required
def edit_board(board_id):
    board = Board.query.get_or_404(board_id)
    form = BoardForm(obj=board)
    if form.validate_on_submit():
        board.name = form.name.data
        board.location_url = form.location_url.data
        board.renewal_date = form.renewal_date.data
        board.renewal_amount = form.renewal_amount.data

        if 'image' in request.files and request.files['image'].filename:
            image = request.files['image']
            if allowed_file(image.filename):
                filename = f"{uuid.uuid4()}_{secure_filename(image.filename)}"
                image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                image.save(image_path)
                board.image = filename
            else:
                flash("Invalid file type! Please upload an image.", "danger")
                return redirect(request.url)

        board.updated_by = current_user.email
        db.session.commit()
        flash('Board updated successfully!', 'success')
        return redirect(url_for('dashboard'))
    return render_template('add_board.html', form=form, board=board)

@app.route('/delete_board/<int:board_id>', methods=['POST'])
@login_required
def delete_board(board_id):
    board = Board.query.get_or_404(board_id)
    db.session.delete(board)
    db.session.commit()
    flash('Board deleted successfully!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/add_user', methods=['GET', 'POST'])
@login_required
def add_user():
    if not current_user.is_admin:
        flash('Access denied! Only admins can add users.', 'danger')
        return redirect(url_for('dashboard'))

    form = UserForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='pbkdf2:sha256', salt_length=16)
        new_user = User(
            email=form.email.data,
            password=hashed_password,
            is_admin=form.is_admin.data
        )
        db.session.add(new_user)
        db.session.commit()
        flash('User added successfully!', 'success')
        return redirect(url_for('dashboard'))
    return render_template('add_user.html', form=form)

if __name__ == '__main__':
    app.run(debug=True)



