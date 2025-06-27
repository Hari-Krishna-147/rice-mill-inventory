from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_user, login_required, logout_user, UserMixin, current_user
from sqlalchemy import func

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret-key-goes-here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# -------------------- MODELS --------------------

class User(UserMixin, db.Model):
    __tablename__='users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

class Stock(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.String(50), nullable=False)
    stock_type = db.Column(db.String(100), nullable=False)
    quantity = db.Column(db.Float, nullable=False)

class Lorry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    number = db.Column(db.String(50), nullable=False)
    driver = db.Column(db.String(100), nullable=False)
    capacity = db.Column(db.Float, nullable=False)

class Trip(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    lorry_id = db.Column(db.Integer, db.ForeignKey('lorry.id'), nullable=False)
    date = db.Column(db.String(50), nullable=False)
    stock_type = db.Column(db.String(100), nullable=False)
    quantity = db.Column(db.Float, nullable=False)
    destination = db.Column(db.String(100), nullable=False)
    status = db.Column(db.String(50), default='In Progress')

    lorry = db.relationship('Lorry', backref='trips')


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials!', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    total_stock = db.session.query(db.func.sum(Stock.quantity)).scalar() or 0
    total_trips = Trip.query.count()

    top_destinations = db.session.query(
        Trip.destination, db.func.count(Trip.destination)
    ).group_by(Trip.destination).order_by(db.func.count(Trip.destination).desc()).limit(3).all()

    trip_data = db.session.query(
        Lorry.number, db.func.count(Trip.id)
    ).join(Trip).group_by(Lorry.number).all()

    return render_template('dashboard.html',
        total_stock=total_stock,
        total_trips=total_trips,
        top_destinations=top_destinations,
        trip_data=trip_data
    )

@app.route('/add_stock', methods=['GET', 'POST'])
@login_required
def add_stock():
    if request.method == 'POST':
        stock = Stock(
            date=request.form['date'],
            stock_type=request.form['stock_type'],
            quantity=float(request.form['quantity'])
        )
        db.session.add(stock)
        db.session.commit()
        flash('Stock added successfully!', 'success')
        return redirect(url_for('view_stock'))
    return render_template('add_stock.html')

@app.route('/view_stock')
@login_required
def view_stock():
    stocks = Stock.query.all()
    return render_template('view_stock.html', stocks=stocks)

@app.route('/add_lorry', methods=['GET', 'POST'])
@login_required
def add_lorry():
    if request.method == 'POST':
        lorry = Lorry(
            number=request.form['number'],
            driver=request.form['driver'],
            capacity=float(request.form['capacity'])
        )
        db.session.add(lorry)
        db.session.commit()
        flash('Lorry added!', 'success')
        return redirect(url_for('view_lorries'))
    return render_template('add_lorry.html')

@app.route('/view_lorries')
@login_required
def view_lorries():
    lorries = Lorry.query.all()
    return render_template('view_lorries.html', lorries=lorries)

@app.route('/edit_lorry/<int:lorry_id>', methods=['GET', 'POST'])
@login_required
def edit_lorry(lorry_id):
    lorry = Lorry.query.get_or_404(lorry_id)
    if request.method == 'POST':
        lorry.number = request.form['number']
        lorry.driver = request.form['driver']
        lorry.capacity = float(request.form['capacity'])
        db.session.commit()
        flash('Lorry updated!', 'success')
        return redirect(url_for('view_lorries'))
    return render_template('edit_lorry.html', lorry=lorry)

@app.route('/delete_lorry/<int:lorry_id>')
@login_required
def delete_lorry(lorry_id):
    lorry = Lorry.query.get_or_404(lorry_id)
    if lorry.trips:
        flash('Cannot delete this lorry. Trips are linked to it.', 'danger')
    else:
        db.session.delete(lorry)
        db.session.commit()
        flash('Lorry deleted.', 'success')
    return redirect(url_for('view_lorries'))

@app.route('/add_trip', methods=['GET', 'POST'])
@login_required
def add_trip():
    lorries = Lorry.query.all()
    if request.method == 'POST':
        trip = Trip(
            lorry_id=request.form['lorry_id'],
            date=request.form['date'],
            stock_type=request.form['stock_type'],
            quantity=float(request.form['quantity']),
            destination=request.form['destination']
        )
        db.session.add(trip)
        db.session.commit()
        flash('Trip added successfully!', 'success')
        return redirect(url_for('view_trips'))
    return render_template('add_trip.html', lorries=lorries)

@app.route('/edit_trip/<int:trip_id>', methods=['GET', 'POST'])
@login_required
def edit_trip(trip_id):
    trip = Trip.query.get_or_404(trip_id)
    lorries = Lorry.query.all()
    if request.method == 'POST':
        trip.date = request.form['date']
        trip.lorry_id = request.form['lorry_id']
        trip.stock_type = request.form['stock_type']
        trip.quantity = float(request.form['quantity'])
        trip.destination = request.form['destination']
        trip.status = request.form['status']
        db.session.commit()
        flash('Trip updated!', 'success')
        return redirect(url_for('view_trips'))
    return render_template('edit_trip.html', trip=trip, lorries=lorries)

@app.route('/delete_trip/<int:trip_id>')
@login_required
def delete_trip(trip_id):
    trip = Trip.query.get_or_404(trip_id)
    db.session.delete(trip)
    db.session.commit()
    flash('Trip deleted.', 'warning')
    return redirect(url_for('view_trips'))

@app.route('/update_status/<int:trip_id>')
@login_required
def update_status(trip_id):
    trip = Trip.query.get_or_404(trip_id)
    trip.status = 'Delivered'
    db.session.commit()
    flash('Marked as Delivered', 'success')
    return redirect(url_for('view_trips'))

@app.route('/view_trips')
@login_required
def view_trips():
    trips = Trip.query.all()
    return render_template('view_trips.html', trips=trips)

@app.route('/report', methods=['GET', 'POST'])
@login_required
def report():
    stock_results = []
    trip_results = []
    selected_date = ""

    if request.method == 'POST':
        selected_date = request.form['date']
        stock_results = Stock.query.filter_by(date=selected_date).all()
        trip_results = Trip.query.filter_by(date=selected_date).all()

    return render_template('report.html',
        selected_date=selected_date,
        stock_results=stock_results,
        trip_results=trip_results
    )
    
    
    # Edit Stock
@app.route('/edit_stock/<int:stock_id>', methods=['GET', 'POST'])
@login_required
def edit_stock(stock_id):
    stock = Stock.query.get_or_404(stock_id)
    if request.method == 'POST':
        stock.date = request.form['date']
        stock.stock_type = request.form['stock_type']
        stock.quantity = float(request.form['quantity'])
        db.session.commit()
        flash('Stock record updated successfully!', 'success')
        return redirect(url_for('view_stock'))
    return render_template('edit_stock.html', stock=stock)


# Delete Stock
@app.route('/delete_stock/<int:stock_id>')
@login_required
def delete_stock(stock_id):
    stock = Stock.query.get_or_404(stock_id)
    db.session.delete(stock)
    db.session.commit()
    flash('Stock record deleted.', 'warning')
    return redirect(url_for('view_stock'))


# User Model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

# Update user loader
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email already exists!', 'danger')
        else:
            new_user = User(email=email, password=password)
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
    return render_template('register.html')

# -------------------- RUN APP --------------------
#if __name__ == '__main__':
 #   app.run(debug=True)