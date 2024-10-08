
# URL Blacklist Manager

URL Blacklist Manager is a Flask-based web application for managing blocked URLs. Users can add, remove, and search for blocked URLs. Additionally, it supports importing and exporting URL data with real-time status updates.

## Features

- Add URLs to be blocked
- Remove blocked URLs
- Search for blocked URLs
- Export URL data as CSV and JSON
- Import URL data from CSV and JSON files
- Real-time import/export status updates

## Installation

### Prerequisites

- Python 3.x
- Flask
- Flask-SQLAlchemy
- Flask-Login
- Flask-WTF
- Flask-SocketIO

### Installation Steps

1. Create a Virtual Environment
    ```bash
    python3 -m venv venv
    ```

2. Activate the Virtual Environment
    ```bash
    # On macOS/Linux
    source venv/bin/activate
    # On Windows
    venv\Scripts\activate
    ```

3. Install the required packages
    ```bash
    pip install Flask Flask-SQLAlchemy Flask-Login Flask-WTF Flask-SocketIO
    ```

4. Run the application
    ```bash
    python app.py
    ```

5. Open your web browser and navigate to [http://127.0.0.1:5001](http://127.0.0.1:5001)

## Project Structure

```
URL Blacklist Manager/
│
├── app.py               # Main application file
├── blacklist.db         # SQLite database
├── templates/           # Folder for HTML Templates
│   ├── index.html
│   └── login.html
└── static/              # Folder for static files like CSS and JS
```

## Usage

### Adding URLs

1. Navigate to the home page
2. Enter the URL to be blocked, category, and reason
3. Click the "Add URL" button

### Removing URLs

1. Navigate to the home page
2. Click the "Remove" button next to the URL you want to remove

### Searching URLs

1. Navigate to the home page
2. Enter the search term in the search box
3. Click the "Search" button

### Exporting Data

1. Navigate to the home page
2. Click the "Export CSV" or "Export JSON" button

### Importing Data

1. Navigate to the home page
2. Select the CSV or JSON file to import
3. Click the "Import" button

## Status Updates

- The import/export status is displayed at the top of the webpage in real-time using WebSocket.

## Code Explanation

### Importing Modules

```python
from datetime import datetime
from flask import Flask, abort, render_template, request, redirect, url_for, flash, jsonify, send_file, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email
from flask_socketio import SocketIO, emit
import csv
import json
from io import StringIO, BytesIO
import os
from sqlalchemy.exc import IntegrityError
```

### Configuration and Initialization

```python
current_dir = os.path.dirname(os.path.abspath(__file__))

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{current_dir}/blacklist.db'
app.config['SQLALCHEMY_BINDS'] = {'user_db': 'sqlite:////Users/seal/Documents/GitHub/url_shortener/user_management/data-dev.sqlite'}
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
socketio = SocketIO(app)
```

### Models

#### User Model

```python
class User(UserMixin, db.Model):
    __bind_key__ = 'user_db'
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(100), nullable=False)
    role_id = db.Column(db.Integer, nullable=False)
```

#### URL Model

```python
class URL(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(500), unique=True, nullable=False)
    category = db.Column(db.String(100), nullable=False)
    date_added = db.Column(db.Date, nullable=False)
    reason = db.Column(db.String(500), nullable=False)
    status = db.Column(db.Boolean, default=True)
```

### Forms

#### LoginForm

```python
class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')
```

### User Loader

```python
@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))
```

### Routes

#### Login

```python
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and check_password_hash(user.password_hash, form.password.data):
            login_user(user)
            return redirect(url_for('index'))
        flash('Invalid email or password', 'danger')
    return render_template('login.html', form=form)
```

#### Logout

```python
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))
```

#### Index

```python
@app.route('/')
@login_required
def index():
    page = request.args.get('page', 1, type=int)
    per_page = 10
    urls = URL.query.paginate(page=page, per_page=per_page)
    return render_template('index.html', urls=urls)
```

#### Add URL

```python
@app.route('/add', methods=['POST'])
@login_required
def add_url():
    url = request.form['url']
    category = request.form['category']
    reason = request.form['reason']
    new_url = URL(url=url, category=category, reason=reason, date_added=db.func.current_date())
    db.session.add(new_url)
    db.session.commit()
    return jsonify({'status': 'success', 'message': 'URL added successfully'})
```

#### Remove URL

```python
@app.route('/remove/<int:id>')
@login_required
def remove_url(id):
    url = db.session.get(URL, id)
    if url is None:
        abort(404)
    db.session.delete(url)
    db.session.commit()
    return jsonify({'status': 'success', 'message': 'URL removed successfully'})
```

#### Toggle Status

```python
@app.route('/toggle/<int:id>')
@login_required
def toggle_status(id):
    url = db.session.get(URL, id)
    if url is None:
        abort(404)
    url.status = not url.status
    db.session.commit()
    return jsonify({'status': 'success', 'message': 'Status updated successfully'})
```

#### Search

```python
@app.route('/search')
@login_required
def search():
    query = request.args.get('query', '')
    page = request.args.get('page', 1, type=int)
    per_page = 10
    urls = URL.query.filter(
        (URL.url.like(f'%{query}%')) |
        (URL.category.like(f'%{query}%')) |
        (URL.reason.like(f'%{query}%'))
    ).paginate(page=page, per_page=per_page)
    return render_template('index.html', urls=urls, query=query)
```

#### Export Data

```python
@app.route('/export/<format>', methods=['GET'])
@login_required
def export_data(format):
    urls = URL.query.all()
    if format == 'csv':
        si = StringIO()
        cw = csv.writer(si)
        cw.writerow(['url', 'category', 'date_added', 'reason', 'status'])
        for url in urls:
            cw.writerow([url.url, url.category, url.date_added, url.reason, url.status])
            socketio.emit('export_progress', {'status': 'Exporting data...', 'url': url.url})
        output = make_response(si.getvalue())
        output.headers["Content-Disposition"] = "attachment; filename=urls.csv"
        output.headers["Content-type"] = "text/csv"
        return output
    elif format == 'json':
        data = [{'url': url.url, 'category': url.category, 'date_added': str(url.date_added), 
                 'reason': url.reason, 'status': url.status} for url in urls]
        output = BytesIO(json.dumps(data, indent=2).encode('utf-8'))
        socketio.emit('export_progress', {'status': 'Exporting data...', 'total': len(data)})
        return send_file(output, mimetype='application/json', as_attachment=True, download_name='urls.json')
    else:
        return jsonify({'error': 'Invalid format'}), 400
```

#### Import Data

```python
@app.route('/import', methods=['POST'])
@login_required
def import_data():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}

), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400
    
    try:
        count = 0
        if file and file.filename.endswith('.csv'):
            stream = StringIO(file.stream.read().decode("UTF8"), newline=None)
            csv_reader = csv.DictReader(stream)
            total_rows = sum(1 for row in csv_reader)
            stream.seek(0)
            csv_reader = csv.DictReader(stream)
            
            for row in csv_reader:
                existing_url = URL.query.filter_by(url=row['url']).first()
                if existing_url:
                    continue
                url = URL(url=row['url'], category=row['category'], 
                          date_added=datetime.strptime(row['date_added'], '%Y-%m-%d').date(), 
                          reason=row['reason'], status=row['status'] in ['1', 'True'])
                db.session.add(url)
                count += 1
                if count % 100 == 0:
                    socketio.emit('import_progress', {'status': 'Importing data...', 'count': count, 'total': total_rows})
            db.session.commit()
            return jsonify({'message': 'CSV imported successfully'}), 200
        elif file and file.filename.endswith('.json'):
            data = json.load(file)
            total_rows = len(data)
            for index, item in enumerate(data):
                existing_url = URL.query.filter_by(url=item['url']).first()
                if existing_url:
                    continue
                url = URL(url=item['url'], category=item['category'], 
                          date_added=datetime.strptime(item['date_added'], '%Y-%m-%d').date(), 
                          reason=item['reason'], status=item['status'] in ['1', 'True'])
                db.session.add(url)
                count += 1
                if count % 100 == 0:
                    socketio.emit('import_progress', {'status': 'Importing data...', 'count': count, 'total': total_rows})
            db.session.commit()
            return jsonify({'message': 'JSON imported successfully'}), 200
        else:
            return jsonify({'error': 'Invalid file format'}), 400
    except IntegrityError:
        db.session.rollback()
        return jsonify({'error': 'An error occurred while importing data'}), 500
```

### Running the Application

```python
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    socketio.run(app, debug=True, port=5001)
```

## Development and Contributions

If you would like to contribute to this project, please fork the project and send a pull request or open an issue to report problems or suggestions.

## License

