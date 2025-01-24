# to create authentication
from functools import wraps
from flask import render_template, request, redirect, url_for, session 


def auth_required(func):
    @wraps(func)
    def inner(*args, **kwargs):
        if 'user_id' in session:
            return func(*args, **kwargs)
        else:
            #flash('Please login to continue')
            return redirect(url_for('login'))
    return inner

# then use the auth required before every route where user needs to be logged in
# example

@app.route('/')
@auth_required
def somefunc():
    return 0

# For the forgot password backend route functionality
# FILE 1 (FLASK ROUTES)

@app.route('/forgot_password')
def forgot_password():
    return render_template('forgotpassword.html')

@app.route('/forgot_password', methods=['POST'])
def forgot_password_post():
    email = request.form.get('email')

    # Check if the email exists in the database
    user = User.query.filter_by(email=email).first()

    if user:
        send_reset_email(user)
        #flash('A reset link has been sent to your email.', 'success')

    else:
        #flash('Email does not exist.', 'danger')
        return redirect(url_for('forgot_password'))
    
    return redirect(url_for('login'))

@app.route('/reset_password')
def reset_password():
    return render_template('resetpassword.html') 

@app.route('/reset_password/<token>', methods=['POST'])
def reset_password_post(token):
    #Validate token post method after html page created
    user = verify_reset_token(token)
    if not user:
        #flash('The reset link is invalid or has expired.', 'danger')
        return redirect(url_for('forgot_password'))
    new_password = request.form.get('password')
    confirm_password = request.form.get('confirm_password')

    if not new_password or new_password != confirm_password:
        #flash('Passwords do not match or are invalid.', 'danger')
        return render_template('resetpassword.html', token=token)
    
    user.password = new_password
    db.session.commit()

    #flash('Your password has been updated. You can now log in.', 'success')
    return redirect(url_for('login'))


# for the actual function sending mails and stuff

# FILE 2

import smtplib
from email.message import EmailMessage

# config is bringing the following things

# MAIL_USERNAME = "SeaGro.off@gmail.com"
# MAIL_PASSWORD = "tldq ulcl gzoq ikcy"
# MAIL_SERVER = "smtp.gmail.com"
# MAIL_PORT = 587

# it was for my prev project, will need to be changed according to our project

from config import MAIL_USERNAME, MAIL_PASSWORD, MAIL_SERVER, MAIL_PORT

def send_email(to_email, subject, body):
    # Create the email
    msg = EmailMessage()
    msg['Subject'] = subject
    msg['From'] = MAIL_USERNAME
    msg['To'] = to_email
    msg.set_content(body)

    # Connect to SMTP server and send email
    with smtplib.SMTP(MAIL_SERVER, MAIL_PORT) as server:
        server.starttls()  # Upgrade the connection to secure
        server.login(MAIL_USERNAME, MAIL_PASSWORD)
        server.send_message(msg)

# FILE 3
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
from flask import url_for 
from models import User
from sendmail import send_email

mail = Mail(app)
# created an instance of the Mail

serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

def generate_reset_token(user):
    return serializer.dumps(user.email, salt='password-reset-salt')

def verify_reset_token(token, expiration=3600):
    try:
        email = serializer.loads(token, salt='password-reset-salt', max_age=expiration)
    except Exception:
        return None
    return User.query.filter_by(email=email).first()

def send_reset_email(user):
    token = generate_reset_token(user)
    reset_url = url_for('reset_password', token=token, _external=True)
    subject = " Reset your password"
    body = f'''
    To reset your password, click the following link:
    {reset_url}

    If you did not make this request, simply ignore this email.
    '''
    send_email(user.email, subject, body)