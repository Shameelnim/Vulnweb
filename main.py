from flask import Flask, request, redirect, url_for, session, render_template_string
import hashlib

app = Flask(__name__)
app.secret_key = 'vulnerable_secret_key'

# Dummy database (for simplicity)
users_db = {}

# Simple hash function (for weak password storage simulation)
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()

# Basic Styles
styles = '''
<style>
    body {
        font-family: Arial, sans-serif;
        background-color: #f4f4f4;
        padding: 20px;
    }
    h2 {
        color: #333;
    }
    form {
        background-color: white;
        padding: 20px;
        border-radius: 5px;
        box-shadow: 0px 0px 10px rgba(0, 0, 0, 0.1);
        max-width: 400px;
        margin: 0 auto;
    }
    input[type="text"], input[type="password"], textarea {
        width: 100%;
        padding: 10px;
        margin: 10px 0;
        border: 1px solid #ddd;
        border-radius: 5px;
    }
    input[type="submit"] {
        background-color: #4CAF50;
        color: white;
        border: none;
        padding: 10px 20px;
        cursor: pointer;
        border-radius: 5px;
        width: 100%;
    }
    input[type="submit"]:hover {
        background-color: #45a049;
    }
    a {
        color: #0066cc;
        text-decoration: none;
    }
    a:hover {
        text-decoration: underline;
    }
</style>
'''

# Vulnerable login page
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Vulnerable SQL Injection simulation (without proper validation)
        if username in users_db and users_db[username] == hash_password(password):
            session['username'] = username
            return redirect(url_for('welcome'))
        else:
            return 'Invalid credentials!'

    login_html = f'''
    {styles}
    <h2>Login</h2>
    <form method="POST">
        Username: <input type="text" name="username" required><br>
        Password: <input type="password" name="password" required><br>
        <input type="submit" value="Login">
    </form>
    <p>Don't have an account? <a href="{{{{ url_for('register') }}}}">Register here</a></p>
    '''
    return render_template_string(login_html)

# Vulnerable registration page
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        # Vulnerable to weak password storage (storing password as MD5 hash)
        if password != confirm_password:
            return 'Passwords do not match!'
        
        if username in users_db:
            return 'Username already exists!'

        users_db[username] = hash_password(password)
        return redirect(url_for('login'))

    register_html = f'''
    {styles}
    <h2>Register</h2>
    <form method="POST">
        Username: <input type="text" name="username" required><br>
        Password: <input type="password" name="password" required><br>
        Confirm Password: <input type="password" name="confirm_password" required><br>
        <input type="submit" value="Register">
    </form>
    <p>Already have an account? <a href="{{{{ url_for('login') }}}}">Login here</a></p>
    '''
    return render_template_string(register_html)

# Welcome page (after login)
@app.route('/welcome')
def welcome():
    if 'username' not in session:
        return redirect(url_for('login'))

    return f'Welcome {session["username"]}'

# XSS Vulnerability (Vulnerable to script injection)
@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        bio = request.form['bio']
        return f'Your bio: {bio}'  # Vulnerable to XSS

    profile_html = f'''
    {styles}
    <h2>Your Profile</h2>
    <form method="POST">
        Bio: <textarea name="bio"></textarea><br>
        <input type="submit" value="Save Bio">
    </form>
    '''
    return render_template_string(profile_html)

# Simulate vulnerable password reset (Weak hash function)
@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        username = request.form['username']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        if new_password != confirm_password:
            return 'Passwords do not match!'

        if username in users_db:
            users_db[username] = hash_password(new_password)
            return redirect(url_for('login'))
        else:
            return 'User not found!'

    reset_password_html = f'''
    {styles}
    <h2>Reset Password</h2>
    <form method="POST">
        Username: <input type="text" name="username" required><br>
        New Password: <input type="password" name="new_password" required><br>
        Confirm New Password: <input type="password" name="confirm_password" required><br>
        <input type="submit" value="Reset Password">
    </form>
    '''
    return render_template_string(reset_password_html)

# Run the app
if __name__ == '__main__':
    app.run(debug=True)
