from flask import Flask, flash, render_template, redirect, request, abort, json, session, url_for
from functools import wraps
from werkzeug.exceptions import HTTPException
from flask_sqlalchemy import Model, SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, current_user, login_required
from flask_bcrypt import Bcrypt, check_password_hash, generate_password_hash
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
from flask_ckeditor import CKEditor
from flask_migrate import Migrate
import random
from datetime import datetime
from flask_user import roles_required, roles_accepted, UserManager, UserMixin
from itsdangerous import  SignatureExpired, URLSafeSerializer
from flask_mail import Mail, Message
from itsdangerous import TimedSerializer,URLSafeTimedSerializer, BadTimeSignature
from werkzeug.utils import secure_filename
import os 
import uuid



app = Flask(__name__)
app.config.from_pyfile('config.py')
login_manager = LoginManager()
login_manager.init_app(app)
db = SQLAlchemy(app)
migrate = Migrate(app, db)
ckeditor = CKEditor(app)
admin = Admin(app)
bcrypt = Bcrypt(app)
token_link = URLSafeTimedSerializer(app.secret_key)


app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True

app.config['MAX_CONTENT_LENGTH'] = 3072 * 3072 
app.config['UPLOAD_EXTENSIONS'] = ['.jpg', '.jpeg', ',png']  
 # all the other configurations are done in config.py file 


mail = Mail(app)
random_code = random.randint(0000, 9999)


# <--Tables Here -->

class MyModelView(ModelView):
    
    def is_accessible(self):
        if current_user.is_anonymous:
            return False
        else:
            return current_user.has_roles('Super Admin')

    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for('adminLogin'))


# Storing Users
class User(db.Model, UserMixin):
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String())
    enrollment_id = db.Column(db.String(), unique=True)
    password = db.Column(db.String())
    email = db.Column(db.String(), unique=True)
    program = db.Column(db.String())
    profile = db.Column(db.String(), unique=True)
    email_verified = db.Column(db.Boolean, default=False)
    email_verified_on = db.Column(db.DateTime())
    roles = db.relationship('Role', secondary='user_roles')


    
    def __repr__(self):
        return f"User('{self.name}', '{self.enrollment_id}')"



class Role(db.Model):
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String())



class UserRoles(db.Model):
    __tablename__ = 'user_roles'

    id = db.Column(db.Integer(), primary_key=True)
    user_id = db.Column(db.Integer(), db.ForeignKey('user.id', ondelete='CASCADE'))
    role_id = db.Column(db.Integer(), db.ForeignKey('role.id', ondelete='CASCADE'))


# Storing Events
class Events(db.Model):
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String())
    language = db.Column(db.String())
    venue = db.Column(db.String())
    date = db.Column(db.String())
    time = db.Column(db.String())
    registration_fee = db.Column(db.String())
    details = db.Column(db.Text())
    contest_id = db.Column(db.Integer(), unique=True)
    status = db.Column(db.String())


    def __repr__(self):
        return f"User('{self.name}')"


# Storing Participants
class Participants(db.Model):
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String())
    enrollment_id = db.Column(db.String())
    email = db.Column(db.String())
    branch = db.Column(db.String())
    semester = db.Column(db.String())
    contest_name = db.Column(db.String())
    contest_id = db.Column(db.Integer())

    def __repr__(self):
        return f"Participants('{self.name}', {self.enrollment_id}', '{self.contest}')"

    
# Storing C Questions
class C(db.Model):
    id = db.Column(db.Integer(), primary_key=True)
    question_title = db.Column(db.String())
    question_statement = db.Column(db.Text())
    sample_input = db.Column(db.String())
    sample_output = db.Column(db.String())
    language = db.Column(db.String())
    level = db.Column(db.String())
    question_link = db.Column(db.String())


    def __repr__(self):
        return f"C('{self.question_title}')"


# Storing C++ Questions
class Cpp(db.Model):
    id = db.Column(db.Integer(), primary_key=True)
    question_title = db.Column(db.String())
    question_statement = db.Column(db.Text())
    sample_input = db.Column(db.String())
    sample_output = db.Column(db.String())
    language = db.Column(db.String())
    level = db.Column(db.String())
    question_link = db.Column(db.String())


    def __repr__(self):
        return f"Cpp('{self.question_title}')"


# Storing Java Questions
class Java(db.Model):
    id = db.Column(db.Integer(), primary_key=True)
    question_title = db.Column(db.String())
    question_statement = db.Column(db.Text())
    sample_input = db.Column(db.String())
    sample_output = db.Column(db.String())
    language = db.Column(db.String())
    level = db.Column(db.String())
    question_link = db.Column(db.String())



    def __repr__(self):
        return f"Java('{self.question_title}')"


# Storing Python Questions
class Python(db.Model):
    id = db.Column(db.Integer(), primary_key=True)
    question_title = db.Column(db.String())
    question_statement = db.Column(db.Text())
    sample_input = db.Column(db.String())
    sample_output = db.Column(db.String())
    language = db.Column(db.String())
    level = db.Column(db.String())
    question_link = db.Column(db.String())



    def __repr__(self):
        return f"Python('{self.question_title}')"


# Storing All Question Questions
class AllQuestions(db.Model):
    id = db.Column(db.Integer(), primary_key=True)
    question_title = db.Column(db.String())
    question_statement = db.Column(db.Text())
    sample_input = db.Column(db.String())
    sample_output = db.Column(db.String())
    language = db.Column(db.String())
    level = db.Column(db.String())


    def __repr__(self):
        return f"AllQuestions('{self.question_title}')"



admin.add_view(MyModelView(User, db.session))
admin.add_view(MyModelView(Events, db.session))
admin.add_view(MyModelView(Participants, db.session))
admin.add_view(MyModelView(C, db.session))
admin.add_view(MyModelView(Cpp, db.session))
admin.add_view(MyModelView(Java, db.session))
admin.add_view(MyModelView(Python, db.session))
admin.add_view(MyModelView(AllQuestions, db.session))
admin.add_view(MyModelView(UserRoles, db.session))
admin.add_view(MyModelView(Role, db.session))

user_manager = UserManager(app, db, User)


# Decorators here to be used further

def login_required(func):
    @wraps(func)
    def secure_function(*args, **kwargs):
        if current_user.is_anonymous:
            return redirect(url_for('adminLogin', next=request.url))
            # return redirect('/admin/login', next=request.url)
        return func(*args, **kwargs)

    return secure_function


def is_admin(func):
    @wraps(func)
    def admin_auth(*args, **kwargs):
        if current_user.has_roles('Super Admin'):
            return redirect('/admin/user')
        if not current_user.has_roles('Admin'):
            # return redirect(url_for('dash_home'))
            return redirect('home')
        return func(*args, **kwargs)

    return admin_auth


def verified_user(func):
    @wraps(func)
    def check_verification(*args, **kwargs):
        if not current_user.email_verified:
            return redirect(url_for('verifyMail'))
        return func(*args, **kwargs)                                                # 'TOO MANY REDIRECT' ERROR SOLVED WITH THIS RETURN 
        
    return check_verification


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))



@app.errorhandler(404)
def page_not_found(e):
    return render_template('404-error-page.html'), 404

# <-- Back-end Logic for Admin Section Only. -->

# Admin sign up logic
@app.route('/admin/sign-up', methods=['GET', 'POST'])
def adminRegistration():
    if request.method == 'POST':
        name = request.form.get('user-name')
        enrollment_id = request.form.get('user-id')
        password = request.form.get('user-password')
        email = request.form.get('user-mail')
        hashed_user_pass = bcrypt.generate_password_hash(password).decode('utf-8')
        add_admin = User(name=name,
                        enrollment_id=enrollment_id,
                        password=hashed_user_pass,
                        email=email,
                        email_verified=False)
        add_admin.roles.append(Role(name='Admin'))
        try:
            db.session.add(add_admin)
            db.session.commit()
            new_user = User.query.filter_by(enrollment_id=enrollment_id).first()
            login_user(new_user)
            return redirect(url_for('verifyMail'))
        except Exception:
            return 'An error occured while creating your account, Try again.', 404
    return render_template('admin-signUp-form.html')

# Sending OTP for email verification 
@app.route('/sendOTP', methods=['GET', 'POST'])
def sendOTP():
    globals()['random_code'] = random.randint(00000, 9999)
    try:
        user_email = current_user.email
        msg = Message('Coders Club -One Time Password', sender='techybadshah@gmail.com', recipients=[user_email])
        msg.body = f'Hi, \n \n To confirm your admin account at Coders Club enter this One Time Password(OTP): \n \n {int(random_code)} \n \n Kind regards \n\n Coders Club'

        mail.send(msg)
    except:
        flash('Something went wrong, Please try after sometimes.', 'otp-sent-fail')
        return redirect(url_for('verifyMail'))
    return redirect(url_for('verifyMail'))

# Email verification page 
@app.route('/verify-mail', methods=['GET', 'POST'])
def verifyMail():    
    if current_user.is_anonymous:
        return redirect(url_for('adminLogin'))
    if current_user.email_verified:
        return redirect(url_for('dash_home'))
    else:
        if request.method == 'POST':
            user_otp = request.form.get('otp-code')
            user = current_user
            try:
                if len(user_otp) == 0:
                    # return 'Enter OTP First'   # FLASH
                    flash('Enter OTP First', 'otp-len-zero')
                    return redirect(url_for('verifyMail'))
                if random_code == int(user_otp):
                    user.email_verified = True
                    user.email_verified_on = datetime.now()
                    db.session.commit()
                    return redirect(url_for('dash_home'))
                else:
                    # return f'Encorrect OTP {user_otp}'     # FLASH
                    flash('Invalid OTP', 'otp-invalid')
                    return redirect(url_for('verifyMail'))
            except:
                return abort(404)
    return render_template('verify-email.html')

# Password reset page
@app.route('/forgot-password', methods=['POST', 'GET'])
def forgotPassword():
    if request.method == 'POST':
        user_email = request.form.get('email')
        try:
            check_email = User.query.filter_by(email=user_email).first()
            user_id = check_email.id
        except Exception:
            return 'No user found with such email'
        if check_email:
            token = token_link.dumps({'user_id':user_id}, salt='password-reset')
            msg = Message('Reset Password', sender='techybadshah@gmail.com', recipients=[user_email], html=render_template('reset-password-link.html', token=token, user=user_id) )
            mail.send(msg)
            flash('Password reset link has been sent to your email', 'pass-forgot-link')
            return redirect(url_for('forgotPassword'))
    return render_template('forgot-pass.html')


@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def resetPassword(token):
    if request.method == 'POST':
        try:
            user = token_link.loads(token, salt='password-reset', max_age=120)['user_id']
            find_user = User.query.filter_by(id=user).first()
            new_password = request.form.get('new-password')
            hash_new_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
            find_user.password = hash_new_password
            db.session.commit()
            login_user(find_user)
            flash('Password changed successfully', 'pass-change-success')
            return redirect(url_for('dash_home'))
        except BadTimeSignature:
            return ' Oops. Something went wrong. Causes for this error may be: <br><br> 1.) The Link has been expired. <br><br> 2.) The link you followed may be broken. '
        except ValueError:
            flash('Enter a new password', 'pass-change-empty')
            return redirect(url_for('resetPassword'))
    return render_template('reset-password.html', token=token)


@app.route('/admin/login', methods=['GET', 'POST'])
def adminLogin():
    if current_user.is_authenticated:
        return redirect(url_for('dash_home'))
    if request.method == 'POST':
        enrollment_id = request.form.get('user-enrollment-id')
        password = request.form.get('user-password')
        final_destination = request.form.get('next')
        check_user = User.query.filter_by(enrollment_id=enrollment_id).first()
        try:
            if check_user and bcrypt.check_password_hash(check_user.password, password) and check_user.has_roles('Admin'):
                login_user(check_user)
                if final_destination:
                    return redirect(final_destination)
                return redirect(url_for('dash_home'))
            elif check_user and bcrypt.check_password_hash(check_user.password, password) and check_user.has_roles('Super Admin'):
                login_user(check_user)
                return redirect('/admin')
            else:
                return 'Encorrect Details', 401
        except:
            return 'Encorrect Details', 401
    return render_template('admin-login.html')


@app.route('/dashboard/home')
@login_required
@verified_user
@is_admin
def dash_home():
    all_events = Events.query.all()
    total_events = Events.query.order_by(-Events.id).first()
    return render_template('/dsb-home.html',
        all_events=all_events,
        total_events=total_events)


@app.route('/dashboard/participants')
@login_required
@is_admin
@verified_user
def show_participants():
        args = request.args
        contest_id = args.get('contest id', None)
        is_there = Participants.query.filter_by(contest_id=contest_id).first()
        if is_there:
            part = 'yes'
            search_id = Participants.query.filter_by(contest_id=contest_id).all()
            return render_template('participants.html',
                                    participants=search_id,
                                    single_participant=is_there, part=part)
        else:
            part = 'no'
            return render_template('participants.html', part=part)


@app.route('/dashboard/add-question', methods=['GET','POST'])
@login_required
@is_admin
@verified_user
def add_question():
    if request.method == 'POST':
        question_title = request.form.get('question-title')
        question_statement = request.form.get('question-statement')
        sample_input = request.form.get('input')
        sample_output = request.form.get('output')
        language = request.form.get('language')
        difficulty_level= request.form.get('difficulty-level')
        question_link = request.form.get('question-link')
        if language == 'C':
            question_data = C(
                        question_title=question_title,
                        question_statement=question_statement,
                        sample_input=sample_input,
                        sample_output=sample_output,
                        language=language,
                        level=difficulty_level,
                        question_link=question_link)
            all_question = AllQuestions(
                        question_title=question_title,
                        question_statement=question_statement,
                        sample_input=sample_input,
                        sample_output=sample_output,
                        language=language,
                        level=difficulty_level)
            db.session.add(question_data)
            db.session.add(all_question)
            db.session.commit()
        elif language == 'C++':
            question_data = Cpp(
                        question_title=question_title,
                        question_statement=question_statement,
                        sample_input=sample_input,
                        sample_output=sample_output,
                        language=language,
                        level=difficulty_level,
                        question_link=question_link)
            all_question = AllQuestions(
                        question_title=question_title,
                        question_statement=question_statement,
                        sample_input=sample_input,
                        sample_output=sample_output,
                        language=language,
                        level=difficulty_level)
            db.session.add(all_question)
            db.session.add(question_data)
            db.session.commit()
        elif language == 'Java':
            question_data = Java(
                        question_title=question_title,
                        question_statement=question_statement,
                        sample_input=sample_input,
                        sample_output=sample_output,
                        language=language,
                        level=difficulty_level,
                        question_link=question_link)
            all_question = AllQuestions(
                        question_title=question_title,
                        question_statement=question_statement,
                        sample_input=sample_input,
                        sample_output=sample_output,
                        language=language,
                        level=difficulty_level)
            db.session.add(all_question)
            db.session.add(question_data)
            db.session.commit()
        elif language == 'Python':
            question_data = Python(
                        question_title=question_title,
                        question_statement=question_statement,
                        sample_input=sample_input,
                        sample_output=sample_output,
                        language=language,
                        level=difficulty_level,
                        question_link=question_link)
            all_question = AllQuestions(
                        question_title=question_title,
                        question_statement=question_statement,
                        sample_input=sample_input,
                        sample_output=sample_output,
                        language=language,
                        level=difficulty_level)
            db.session.add(all_question)
            db.session.add(question_data)
            db.session.commit()
        flash('Question Added ', 'new-question-added')
        return redirect('/dashboard/add-question')
    return render_template('add-question.html')


@app.route('/dashboard/edit-question/<string:language>/<int:id>', methods=['GET', 'POST'])
@login_required
@is_admin
@verified_user
def edit_question(language, id):
    if language == 'Python':    
        update = Python.query.get(id)
    elif language == 'C++':
        update = Cpp.query.get(id)
    elif language == 'C':
        update = C.query.get(id)
    elif language == 'Java':
        update = Java.query.get(id)
    if request.method == 'POST':
            update.question_title = request.form.get('question-title')
            update.question_statement = request.form.get('language')
            update.sample_input = request.form.get('input')
            update.sample_output = request.form.get('output')
            update.language = request.form.get('language')
            update.level = request.form.get('difficulty-level')
            db.session.commit()
            return redirect('/dashboard/all-questions?question=c')
    return render_template('edit-question.html', update=update)



@app.route('/delete-question/<string:language>/<int:id>', methods=['GET', 'POST'])
@login_required
@is_admin
@verified_user
def delete_question(language, id):
        if language == 'Python':    
            remove = Python.query.get_or_404(id)
            db.session.delete(remove)
            db.session.commit()
            return redirect('/dashboard/all-questions?question=python')
        elif language == 'C++':
            remove = Cpp.query.get_or_404(id)
            db.session.delete(remove)
            db.session.commit()
            return redirect('/dashboard/all-questions?question=cpp')
        elif language == 'C':
            remove = C.query.get_or_404(id)
            db.session.delete(remove)
            db.session.commit()
            return redirect('/dashboard/all-questions?question=c')
        elif language == 'Java':
            remove = Java.query.get_or_404(id)
            db.session.delete(remove)
            db.session.commit()
            return redirect('/dashboard/all-questions?question=java')
        else:
            return abort(404)


# <-- Querying Different Languages with difficulty levels on Admin Dashboard  -->

@app.route('/dashboard/all-questions', methods=['GET', 'POST'])
@login_required
@is_admin
@verified_user
def show_questions_dashboard():
    args = request.args
    level = args.get('level', None)
    questions = args.get('question', None)

    # Fetching total number of questions in each language

    number_in_python = Python.query.order_by(-Python.id).first()
    number_in_c = C.query.order_by(-C.id).first()
    number_in_cpp = Cpp.query.order_by(-Cpp.id).first()
    number_in_java = Java.query.order_by(-Java.id).first()

    # <-- Querying Java questions according to difficulty level -->
    if questions == 'java' and level == 'easy':
        all_question = Java.query.filter_by(level='Easy')
        que_language = Java.query.filter_by(id=1).first()
        return render_template('dashboard-questions.html', all_question=all_question, que_language=que_language,questions=questions, number_in_python=number_in_python,
                                number_in_c=number_in_c,
                                number_in_cpp=number_in_cpp,
                                number_in_java=number_in_java)
    elif questions == 'java' and level == 'medium':
        all_question = Java.query.filter_by(level='Medium')
        que_language = Java.query.filter_by(id=1).first()
        return render_template('dashboard-questions.html', all_question=all_question, que_language=que_language,questions=questions, number_in_python=number_in_python,
                                number_in_c=number_in_c,
                                number_in_cpp=number_in_cpp,
                                number_in_java=number_in_java)
    elif questions == 'java' and level == 'hard':
        all_question = Java.query.filter_by(level='Hard')
        que_language = Java.query.filter_by(id=1).first()
        return render_template('dashboard-questions.html', all_question=all_question, que_language=que_language,questions=questions, number_in_python=number_in_python,
                                number_in_c=number_in_c,
                                number_in_cpp=number_in_cpp,
                                number_in_java=number_in_java)
    elif questions == 'java':
        all_question = Java.query.all()
        que_language = Java.query.filter_by(id=1).first()
        return render_template('dashboard-questions.html', all_question=all_question, que_language=que_language,questions=questions, number_in_python=number_in_python,
                                number_in_c=number_in_c,
                                number_in_cpp=number_in_cpp,
                                number_in_java=number_in_java)
    # <-- Querying C questions according to difficulty level -->
    elif questions == 'c' and level == 'easy':
        all_question = C.query.filter_by(level='Easy')
        que_language = C.query.filter_by(id=1).first()
        return render_template('dashboard-questions.html', all_question=all_question, que_language=que_language,questions=questions, number_in_python=number_in_python,
                                number_in_c=number_in_c,
                                number_in_cpp=number_in_cpp,
                                number_in_java=number_in_java)
    elif questions == 'c' and level == 'medium':
        all_question = C.query.filter_by(level='Medium')
        que_language = C.query.filter_by(id=1).first()
        return render_template('dashboard-questions.html', all_question=all_question, que_language=que_language,questions=questions, number_in_python=number_in_python,
                                number_in_c=number_in_c,
                                number_in_cpp=number_in_cpp,
                                number_in_java=number_in_java)    
    elif questions == 'c' and level == 'hard':
        all_question = C.query.filter_by(level='Hard')
        que_language = C.query.filter_by(id=1).first()
        return render_template('dashboard-questions.html', all_question=all_question, que_language=que_language,questions=questions, number_in_python=number_in_python,
                                number_in_c=number_in_c,
                                number_in_cpp=number_in_cpp,
                                number_in_java=number_in_java)
    elif questions == 'c':
        all_question = C.query.all()
        que_language = C.query.filter_by(id=1).first()
        return render_template('dashboard-questions.html', all_question=all_question, que_language=que_language,questions=questions, number_in_python=number_in_python,
                                number_in_c=number_in_c,
                                number_in_cpp=number_in_cpp,
                                number_in_java=number_in_java)
     # <-- Querying C++ questions according to difficulty level -->
    elif questions == 'cpp' and level == 'easy':
        all_question = Cpp.query.filter_by(level='Easy')
        que_language = Cpp.query.filter_by(id=1).first()
        return render_template('dashboard-questions.html', all_question=all_question, que_language=que_language, questions=questions, number_in_python=number_in_python,
                                number_in_c=number_in_c,
                                number_in_cpp=number_in_cpp,
                                number_in_java=number_in_java)
    elif questions == 'cpp' and level == 'medium':
        all_question = Cpp.query.filter_by(level='Medium')
        que_language = Cpp.query.filter_by(id=1).first()
        return render_template('dashboard-questions.html', all_question=all_question, que_language=que_language, questions=questions, number_in_python=number_in_python,
                                number_in_c=number_in_c,
                                number_in_cpp=number_in_cpp,
                                number_in_java=number_in_java)
    elif questions == 'cpp' and level == 'hard':
        all_question = Cpp.query.filter_by(level='Hard')
        que_language = Cpp.query.filter_by(id=1).first()
        return render_template('dashboard-questions.html', all_question=all_question, que_language=que_language, questions=questions, number_in_python=number_in_python,
                                number_in_c=number_in_c,
                                number_in_cpp=number_in_cpp,
                                number_in_java=number_in_java)
    elif questions == 'cpp':
        all_question = Cpp.query.all()
        que_language = Cpp.query.filter_by(id=1).first()
        return render_template('dashboard-questions.html', all_question=all_question, que_language=que_language, questions=questions, number_in_python=number_in_python,
                                number_in_c=number_in_c,
                                number_in_cpp=number_in_cpp,
                                number_in_java=number_in_java)
    # <-- Querying Python questions according to difficulty level -->
    elif questions == 'python' and level == 'easy':
        all_question = Python.query.filter_by(level='Easy')
        que_language = Python.query.filter_by(id=1).first()
        return render_template('dashboard-questions.html', all_question=all_question, que_language=que_language, questions=questions, number_in_python=number_in_python,
                                number_in_c=number_in_c,
                                number_in_cpp=number_in_cpp,
                                number_in_java=number_in_java)
    elif questions == 'python' and level == 'medium':
        all_question = Python.query.filter_by(level='Medium')
        que_language = Python.query.filter_by(id=1).first()
        return render_template('dashboard-questions.html', all_question=all_question, que_language=que_language, questions=questions, number_in_python=number_in_python,
                                number_in_c=number_in_c,
                                number_in_cpp=number_in_cpp,
                                number_in_java=number_in_java)
    elif questions == 'python' and level == 'hard':
        all_question = Python.query.filter_by(level='Hard')
        que_language = Python.query.filter_by(id=1).first()
        return render_template('dashboard-questions.html', all_question=all_question, que_language=que_language, questions=questions, number_in_python=number_in_python,
                                number_in_c=number_in_c,
                                number_in_cpp=number_in_cpp,
                                number_in_java=number_in_java)
    elif questions == 'python':
        all_question = Python.query.all()
        que_language = Python.query.filter_by(id=1).first()
        return render_template('dashboard-questions.html',
                                all_question=all_question,
                                que_language=que_language,
                                questions=questions,
                                number_in_python=number_in_python,
                                number_in_c=number_in_c,
                                number_in_cpp=number_in_cpp,
                                number_in_java=number_in_java)
    else:
        return "ERROR ! Check URL and try again", 404


@app.route('/dashboard/add-event', methods=['GET', 'POST'])
@login_required
@is_admin
@verified_user
def add_event():
    if request.method == 'POST':
        event_name = request.form.get('event-name')
        language = request.form.get('language')
        venue = request.form.get('venue')
        date = request.form.get('date')
        time  = request.form.get('time')
        registration_fee = request.form.get('registration-fee')
        event_details = request.form.get('event-details')
        random_id = [x for x in range(0000, 9999)]
        contest_id = random.choice(random_id)
        year = date[0:4]
        month = date[5:7]
        day = date[8:10]
        formatted_date = f'{day}/{month}/{year}'
        add_event = Events(name=event_name,
                           language=language,
                           venue=venue,
                           date=formatted_date,
                           time=time,
                           registration_fee=registration_fee,
                           details=event_details,
                           contest_id=contest_id, status='Scheduled')
        try:
            db.session.add(add_event)
            db.session.commit()
            flash('Event Added', 'new-event-added')
            return redirect('/dashboard/add-event')
        except Exception:
            return "Oops! looks like it was server's fault, Try reloading this page or go back", 404
    all_events = Events.query.order_by(-Events.id).all()
    return render_template('add-event.html', all_events=all_events)


@app.route('/dashboard/edit-event/<int:id>', methods=['GET', 'POST'])
@login_required
@is_admin
@verified_user
def edit_event(id):
    update = Events.query.get_or_404(id)
    if request.method == 'POST':
        update.name = request.form.get('event-name')
        update.language = request.form.get('language')
        update.venue = request.form.get('venue')
        date = request.form.get('date')
        year = date[0:4]
        month = date[5:7]
        day = date[8:10]
        formatted_date = f'{day}/{month}/{year}'
        update.date = formatted_date
        update.time = request.form.get('time')
        update.registration_fee = request.form.get('registration-fee')
        update.details = request.form.get('event-details')
        db.session.commit()
        return redirect('/dashboard/add-event')
    all_events = Events.query.order_by(-Events.id).all()
    return render_template('edit-event.html', update=update, all_events=all_events)


@app.route('/event/<int:id>', methods=['GET', 'POST'])
@login_required
@is_admin
@verified_user
def event_status(id):
    args = request.args
    find = Events.query.get_or_404(id)
    status = args.get('status')
    if status == 'Completed':
        find.status = 'Completed'
        db.session.commit()
        return redirect('/dashboard/add-event')
    else:
        return abort(404)


@app.route('/delete-event/<int:id>', methods=['GET', 'POST'])
@login_required
@is_admin
@verified_user
def delete_event(id):
    erase = Events.query.get_or_404(id)
    db.session.delete(erase)
    db.session.commit()
    flash('Event Deleted', 'event-deleted')
    return redirect('/dashboard/add-event')


@app.route('/my-profile', methods=['GET', 'POST'])
@login_required
@is_admin
@verified_user
def myProfile():
    return render_template('update-profile.html')


@app.route('/upload-file', methods=['GET', 'POST'])
def fileUpload():
    images = os.listdir(app.config['UPLOAD_PATH'])
    user  = current_user
    if request.method == 'POST':
        uploaded_file = request.files['file']
        file_name = secure_filename(uploaded_file.filename)
        if file_name != '':
            file_extension_check = os.path.splitext(file_name)[1]
            if file_extension_check not in app.config['UPLOAD_EXTENSIONS']:
                return 'file extension not supported'
            unique_name = uuid.uuid4()
            user_name_on_file  = str(unique_name) + str(file_extension_check)
            current_profile_name = user.profile
            if current_user.profile != None:
                path = app.config['UPLOAD_PATH'] + '/' + current_profile_name
                os.remove(path)
                uploaded_file.save(os.path.join(app.config['UPLOAD_PATH'], user_name_on_file))
            else:
                uploaded_file.save(os.path.join(app.config['UPLOAD_PATH'], user_name_on_file))
            user.profile = user_name_on_file
            db.session.commit()
        return redirect(url_for('myProfile'))


@app.route('/update-profile', methods=['GET', 'POST'])
def updateProfile():
    if request.method == 'POST':
        name_to_update = request.form.get('user-name')
        program_to_update = request.form.get('user-program')
        password_to_update = request.form.get('user-password')
        if len(password_to_update) != 0 :
            hash_updated_pass = bcrypt.generate_password_hash(password_to_update).decode('utf-8')
        user = current_user
        if len(password_to_update) == 0:
            user.name = name_to_update
            user.program = program_to_update
            db.session.commit()
            flash('Account Details Updated', 'profile-update')
            return redirect(url_for('myProfile'))
        elif len(password_to_update) != 0 :
            user.name = name_to_update
            user.program = program_to_update
            user.password = hash_updated_pass
            db.session.commit()
            flash('Account Details Updated', 'profile-update')
            return redirect(url_for('myProfile'))
    return redirect(url_for('myProfile'))
    

# <-- Admin section logic end here -->




# <-- Back-end Logic for All type Users -->


@app.route('/')
def home():
    return render_template('home.html')


# <-- Querying Different Languages with different difficulty levels -->
@app.route('/problems', methods=['GET', 'POST'])
def show_questions():
    args = request.args
    level = args.get('level', None)
    questions = args.get('question', None)
    # <-- Querying Java questions according to difficulty level -->
    if questions == 'java' and level == 'easy':
        all_question = Java.query.filter_by(level='Easy').all()
        que_language = Java.query.filter_by(id=1).first()
        return render_template('problems-page.html', all_question=all_question, que_language=que_language)
    elif questions == 'java' and level == 'medium':
        all_question = Java.query.filter_by(level='Medium').all()
        que_language = Java.query.filter_by(id=1).first()
        return render_template('problems-page.html', all_question=all_question, que_language=que_language)
    elif questions == 'java' and level == 'hard':
        all_question = Java.query.filter_by(level='Hard').all()
        que_language = Java.query.filter_by(id=1).first()
        return render_template('problems-page.html', all_question=all_question, que_language=que_language)
    elif questions == 'java':
        all_question = Java.query.all()
        que_language = Java.query.filter_by(id=1).first()
        return render_template('problems-page.html', all_question=all_question, que_language=que_language)
    # <-- Querying C questions according to difficulty level -->
    elif questions == 'c' and level == 'easy':
        all_question = C.query.filter_by(level='Easy').all()
        que_language = C.query.filter_by(id=1).first()
        return render_template('problems-page.html', all_question=all_question, que_language=que_language)
    elif questions == 'c' and level == 'medium':
        all_question = C.query.filter_by(level='Medium').all()
        que_language = C.query.filter_by(id=1).first()
        return render_template('problems-page.html', all_question=all_question, que_language=que_language)    
    elif questions == 'c' and level == 'hard':
        all_question = C.query.filter_by(level='Hard').all()
        que_language = C.query.filter_by(id=1).first()
        return render_template('problems-page.html', all_question=all_question, que_language=que_language)
    elif questions == 'c':
        all_question = C.query.all()
        que_language = C.query.filter_by(id=1).first()
        return render_template('problems-page.html', all_question=all_question, que_language=que_language)
     # <-- Querying C++ questions according to difficulty level -->
    elif questions == 'cpp' and level == 'easy':
        all_question = Cpp.query.filter_by(level='Easy').all()
        que_language = Cpp.query.filter_by(id=1).first()
        return render_template('problems-page.html', all_question=all_question, que_language=que_language)
    elif questions == 'cpp' and level == 'medium':
        all_question = Cpp.query.filter_by(level='Medium').all()
        que_language = Cpp.query.filter_by(id=1).first()
        return render_template('problems-page.html', all_question=all_question, que_language=que_language)
    elif questions == 'cpp' and level == 'hard':
        all_question = Cpp.query.filter_by(level='Hard').all()
        que_language = Cpp.query.filter_by(id=1).first()
        return render_template('problems-page.html', all_question=all_question, que_language=que_language)
    elif questions == 'cpp':
        all_question = Cpp.query.all()
        que_language = Cpp.query.filter_by(id=1).first()
        return render_template('problems-page.html', all_question=all_question, que_language=que_language)
    # <-- Querying Python questions according to difficulty level -->
    elif questions == 'python' and level == 'easy':
        all_question = Python.query.filter_by(level='Easy').all()
        que_language = Python.query.filter_by(id=1).first()
        return render_template('problems-page.html', all_question=all_question, que_language=que_language)
    elif questions == 'python' and level == 'medium':
        all_question = Python.query.filter_by(level='Medium').all()
        que_language = Python.query.filter_by(id=1).first()
        return render_template('problems-page.html', all_question=all_question, que_language=que_language)
    elif questions == 'python' and level == 'hard':
        all_question = Python.query.filter_by(level='Hard').all()
        que_language = Python.query.filter_by(id=1).first()
        return render_template('problems-page.html', all_question=all_question, que_language=que_language)
    elif questions == 'python':
        all_question = Python.query.all()
        que_language = Python.query.filter_by(id=1).first()
        return render_template('problems-page.html', all_question=all_question, que_language=que_language)
    else:
        return "ERROR ! Check URL and try again", 404


@app.route('/contest-registration/q_event', methods=['GET', 'POST'])
def user_event():
    args = request.args
    event_id = args.get('event id', None)
    query_id = Events.query.filter_by(contest_id=event_id).first()
    if query_id:
        if request.method == 'POST':
            name = request.form.get('participant-name')
            enrollment_id = request.form.get('enrollment-id')
            email = request.form.get('email')
            branch = request.form.get('branch-name')
            semester = request.form.get('current-semester')
            contest_name = request.form.get('contest-name')
            contest_id = request.form.get('contest-id')
            add_participant = Participants(name=name,
                                           enrollment_id=enrollment_id,
                                           email=email,
                                           branch=branch,
                                           semester=semester,
                                           contest_name=contest_name,
                                           contest_id=contest_id)
            db.session.add(add_participant)
            db.session.commit()
            flash('Registration Successfull', 'event-register-success')
            return redirect(request.referrer)     # Redirect on same page OR (request.url)-> works same
        elif query_id.status == 'Completed':
            return "<h2>Oooooops !  YOU ARE LATE</h2>  <br>  <h4> The Event has been completed and closed, watch for upcoming events! </h4>"
        return render_template('auto-contest-registration.html', contest_main_id=query_id)
    else:
        return abort(404)


@app.route('/contest/<int:id>', methods=['GET', 'POST'])
def events_page(id):

        event = Events.query.filter_by(contest_id=id).first()
        if event:
            return render_template('contest-details.html', event=event)
        else:
            return abort(404)


@app.route('/upcoming-contests')
def all_events():
    events = Events.query.order_by(-Events.id).all()
    now_date = datetime.now()
    current_year = str(now_date.year)
    current_month = str(now_date.month)
    current_day = str(now_date.day)
    return render_template('contests.html', events=events,
                                                                current_year=current_year,
                                                                current_month=current_month,
                                                                current_day=current_day)


@app.route('/about-us')
def aboutUs():
    return render_template('about-us.html')


@app.route('/contact-us')
def contactUs():
    return render_template('contact-us.html')

@app.route('/logout')
def logout():
    if current_user.is_authenticated:
        logout_user()
        return redirect(url_for('adminLogin'))
    else:
        return redirect(url_for('adminLogin'))
        

# @app.route('/test-page')
# def testPage():
#     a = Python.query.order_by(-Python.id).first()

#     if a:
#         return str(a.id)
#     else:
#         return 'No Question Added'

if __name__ == '__main__':
    app.run(debug=False)

