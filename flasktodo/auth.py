import functools

from flask import (
    Blueprint, flash, g, redirect, render_template, request, session, url_for
)
from werkzeug.security import check_password_hash, generate_password_hash

from flasktodo.db import get_db

# This creates a Blueprint named 'auth'.
# Like the application object, the blueprint needs to know where it’s defined, so __name__ is passed as the second argument.
# The url_prefix will be prepended to all the URLs associated with the blueprint.
bp = Blueprint('auth', __name__, url_prefix='/auth')


# @bp.route associates the URL /register with the register view function.
# When Flask receives a request to /auth/register, it will call the register view and use the return value as the response.
@bp.route('/register', methods=('GET', 'POST'))
def register():
    if request.method == 'POST':
        name = request.form['name']
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        db = get_db()
        error = None

        if not username:
            error = 'Username is required.'
        elif not password:
            error = 'Password is required.'
        elif not name:
            error = 'Name is required.'
        elif not email:
            error = 'Email is required.'
        elif db.execute(
            'SELECT id FROM user WHERE username = ?', (username,)
            ).fetchone() is not None:
            error = 'User {} is already registered.'.format(username)
        elif db.execute(
            'SELECT id FROM user WHERE name = ?', (name,)
            ).fetchone() is not None:
            error = 'Name {} is already registered.'.format(name)
        elif db.execute(
            'SELECT id FROM user WHERE email = ?', (email,)
            ).fetchone() is not None:
            error = 'Email {} is already registered.'.format(email)
        if error is None:
            db.execute(
                'INSERT INTO user (name, username, email, password) VALUES (?, ?, ?, ?)',
                (name, username, email, generate_password_hash(password)) # generate_password_hash() is used to securely hash the password, and that hash is stored.
            )
            db.commit() # Since this query modifies data, db.commit() needs to be called afterwards to save the changes.
            return redirect(url_for('auth.login')) # redirect() generates a redirect response to the generated URL.
            # If validation fails, the error is shown to the user.
        flash(error) # flash() stores messages that can be retrieved when rendering the template.

    return render_template('auth/register.html') # render_template() will render a template containing the HTML.


@bp.route('/login', methods=('GET', 'POST'))
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        db = get_db()
        error = None
        user = db.execute(
            'SELECT * FROM user WHERE username = ?', (username,)
        ).fetchone()
        email = db.execute(
            'SELECT * FROM user WHERE email = ?', (email,)
        ).fetchone()

        if user is None or email is None:
            error = 'Incorrect Username or Email.'
            # check_password_hash() hashes the submitted password in the same way as the stored hash and securely compares them. If they match, the password is valid.

        elif not check_password_hash(user['password'], password):
            error = 'Incorrect password. Try again.'

        if error is None:
            session.clear()
            session['user_id'] = user['id']
            return redirect(url_for('index'))

        flash(error)

    return render_template('auth/login.html')


# bp.before_app_request() registers a function that runs before the view function, no matter what URL is requested.
@bp.before_app_request
# load_logged_in_user checks if a user id is stored in the session and gets that user’s data from the database, storing it on g.user, which lasts for the length of the request.
def load_logged_in_user():
    user_id = session.get('user_id')
    # If there is no user id, or if the id doesn’t exist, g.user will be None.
    if user_id is None:
        g.user = None
    else:
        g.user = get_db().execute(
            'SELECT * FROM user WHERE id = ?', (user_id,)
        ).fetchone()

# To log out, you need to remove the user id from the session. Then load_logged_in_user won’t load a user on subsequent requests.
@bp.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))
