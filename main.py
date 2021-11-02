from flask import Flask, app, jsonify, request, session, render_template, make_response
from functools import wraps
from flask.helpers import make_response
import jwt
import datetime

from flask.templating import render_template


app = Flask(__name__)
app.config['SECRET_KEY'] = 'JustDemonstrating'


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.args.get('token') 

        if not token:
            return jsonify({'message' : 'Token is missing!'}), 403

        try: 
            data = jwt.decode(token, app.config['SECRET_KEY'])
        except:
            return jsonify({'message' : 'Token is invalid!'}), 403

        return f(*args, **kwargs)

    return decorated

@app.route('/')
def index():
    if not session.get('logged_in'):
        return render_template('login.html')
    else:
        return "Iniciado"

@app.route('/auth')
@token_required
def authorised():
    return 'Visible solo con un token valido'

@app.route('/login', methods=['POST'])
def login():
    if request.form['username'] and request.form['cardnumber'] and request.form['expirated'] and request.form['ccv'] and request.form['password'] == 'password':
        session['logged_in'] = True
        token = jwt.encode({
            'user': request.form['username'],
            'cardnumer': request.form['cardnumber'],
            'expirated': request.form['expirated'],
            'cvv': request.form['ccv'],
            'exp': datetime.datetime.utcnow() + datetime.timedelta(seconds=60)
        }, app.config['SECRET_KEY'])
        print(token)
        resuelto = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        print(resuelto)
        return jsonify({'token': token.decode('utf-8')})
    else:
        return make_response('No se puede verificar', 403, {'WWW-Authenticate' : 'Basic realm="Login Required"'})


if __name__ == '__main__':
    app.run(debug=True)