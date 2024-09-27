from datetime import datetime

import bcrypt
from flask_login import (LoginManager, UserMixin, current_user, login_required,
                         login_user, logout_user)
from flask_sqlalchemy import SQLAlchemy

from flask import Flask, redirect, render_template, request, session

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.secret_key = 'your_secret_key'  
db = SQLAlchemy(app)
login_manager = LoginManager(app)

class User(db.Model, UserMixin):  
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(120), unique=True)  
    password = db.Column(db.String(100))
    role = db.Column(db.String(50), nullable=False)

    def __init__(self, username, email, password, role):
        self.username = username
        self.email = email
        self.role = role
        self.password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    def check_password(self, password):
        return bcrypt.checkpw(password.encode('utf-8'), self.password.encode('utf-8'))

class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)
    deadline = db.Column(db.DateTime, nullable=False)
    status = db.Column(db.String(50), nullable=False, default="Not Started")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    
    
    
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

with app.app_context():
    # db.drop_all()  
    db.create_all()



@app.route('/')
@login_required
def dashboard():
    if current_user.role == 'admin':
        users_list = User.query.filter_by(role='user').all()
        adminflag = True
        return render_template('dashboard.html', data=adminflag,users_list=users_list)
    else:
        adminflag = False
        tasks = Task.query.filter_by(username=current_user.username).all()
        if tasks:
            return render_template('userSide.html', tasks=tasks)
        return render_template('dashboard.html', data=adminflag)
    
@app.route('/user/<username>')
@login_required
def user_status(username):
    tasks = Task.query.filter_by(username=username).all()
    print(tasks)
    if tasks:
        return render_template('userStatus.html', tasks=tasks)
    return render_template('userStatus.html')

@app.route('/addTask', methods=['POST'])
@login_required
def add_task():
    username = request.form['username']
    title1 = request.form['title']
    description = request.form['description']
    deadlineinput = request.form['deadline']
    deadline = datetime.strptime(deadlineinput, '%Y-%m-%d')
    
    tasks = Task.query.filter_by(title=title1).first()
    if tasks:
        return redirect('/user/' + username)
    
    new_task = Task(
        username=username,
        title=title1,
        description=description,
        deadline=deadline,
        status='Initial',
        created_at=datetime.utcnow()
    )
    
    db.session.add(new_task)
    db.session.commit()
    
    return redirect('/user/' + username)


@app.route('/updatestatus/<username1>/<title1>',methods=['POST'])
@login_required
def updatestatus(username1,title1):
    task = Task.query.filter_by(username=username1 , title=title1).first()
    task.status=request.form['status']
    db.session.add(task)
    db.session.commit()
    return redirect('/')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        role = request.form['role']
        
        # Check if user already exists
        if User.query.filter_by(email=email).first() is not None:
            return "Email already registered", 400  # Handle error
        
        new_user = User(username=username, email=email, password=password, role=role)
        db.session.add(new_user)
        db.session.commit()
        return redirect('/login')
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login_view():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        print(user)
        if user and user.check_password(password):
            login_user(user) 
            return redirect('/')
        return "Invalid username or password", 401 

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect('/login')




if __name__ == '__main__':
    app.run(debug=True)
