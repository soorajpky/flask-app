from flask import Flask, render_template, redirect, url_for, request, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.utils import secure_filename
from models import db, User, Board, bcrypt
import os
from datetime import datetime, timedelta
from flask_migrate import Migrate
from flask_wtf.csrf import CSRFProtect
from forms import LoginForm, BoardForm, UserForm

app = Flask(__name__)
app.config.from_object('config.Config')

# Initialize CSRF protection
csrf = CSRFProtect()
csrf.init_app(app)

db.init_app(app)

# Initialize Flask-Migrate
migrate = Migrate(app, db)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Initialize the database and create an admin user if not already present
with app.app_context():
    db.create_all()
    if not User.query.filter_by(email="admin@example.com").first():
        hashed_password = bcrypt.generate_password_hash("admin123").decode('utf-8')
        admin_user = User(email="admin@example.com", password=hashed_password, is_admin=True)
        db.session.add(admin_user)
        db.session.commit()

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('Invalid credentials', 'danger')
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/')
@login_required
def dashboard():
    boards = Board.query.all()

    # Check for boards with renewal dates within the next 7 days
    alert_boards = [
        board for board in boards
        if board.renewal_date and 0 <= (board.renewal_date - datetime.today().date()).days <= 7
    ]

    return render_template('dashboard.html', boards=boards, alert_boards=alert_boards)

@app.route('/add_board', methods=['GET', 'POST'])
@login_required
def add_board():
    form = BoardForm()
    if form.validate_on_submit():
        name = form.name.data
        location_url = form.location_url.data
        renewal_date = form.renewal_date.data
        renewal_amount = form.renewal_amount.data

        if 'image' in request.files and request.files['image'].filename:
            image_file = request.files['image']
            filename = secure_filename(image_file.filename)
            image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            image_file.save(image_path)
        else:
            filename = None

        board = Board(name=name, location_url=location_url, renewal_date=renewal_date,
                      renewal_amount=renewal_amount, image=filename, updated_by=current_user.email)
        db.session.add(board)
        db.session.commit()
        flash('Board added successfully!', 'success')
        return redirect(url_for('dashboard'))
    return render_template('add_board.html', form=form)

@app.route('/add_user', methods=['GET', 'POST'])
@login_required
def add_user():
    if not current_user.is_admin:
        flash('Only admins can add users!', 'danger')
        return redirect(url_for('dashboard'))

    form = UserForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        is_admin = form.is_admin.data
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        user = User(email=email, password=hashed_password, is_admin=is_admin)
        db.session.add(user)
        db.session.commit()
        flash('User added successfully!', 'success')
        return redirect(url_for('dashboard'))

    return render_template('add_user.html', form=form)

@app.route('/delete_board/<int:board_id>')
@login_required
def delete_board(board_id):
    board = Board.query.get_or_404(board_id)
    if current_user.is_admin or board.updated_by == current_user.email:
        db.session.delete(board)
        db.session.commit()
        flash('Board deleted successfully!', 'success')
    else:
        flash('You do not have permission to delete this board!', 'danger')
    return redirect(url_for('dashboard'))

@app.route('/edit_board/<int:board_id>', methods=['GET', 'POST'])
@login_required
def edit_board(board_id):
    board = Board.query.get_or_404(board_id)
    if current_user.is_admin or board.updated_by == current_user.email:
        form = BoardForm(obj=board)
        if form.validate_on_submit():
            board.name = form.name.data
            board.location_url = form.location_url.data
            board.renewal_date = form.renewal_date.data
            board.renewal_amount = form.renewal_amount.data
            board.updated_by = current_user.email
            if 'image' in request.files and request.files['image'].filename:
                image_file = request.files['image']
                filename = secure_filename(image_file.filename)
                image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                image_file.save(image_path)
                board.image = filename
            db.session.commit()
            flash('Board updated successfully!', 'success')
            return redirect(url_for('dashboard'))
        return render_template('add_board.html', form=form, board=board)
    else:
        flash('You do not have permission to edit this board!', 'danger')
        return redirect(url_for('dashboard'))

if __name__ == '__main__':
    app.run(debug=True)

