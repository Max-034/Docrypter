from flask import Flask, request, jsonify , send_file , url_for , redirect , session
import os , json
from supabase import create_client, Client
from PyPDF2 import PdfReader , PdfWriter
from authlib.integrations.flask_client import OAuth
import google.oauth2.credentials
import google_auth_oauthlib.flow
import os
from supabase import create_client, Client
from jinja2 import Environment, FileSystemLoader
import code
from oauthlib.oauth2 import WebApplicationClient
import requests
from functools import wraps
from werkzeug.security import check_password_hash, generate_password_hash
import uuid


from flask_login import (
    LoginManager,
    current_user,
    login_required,
    login_user,
    logout_user,
)

appConf = {
    "OAUTH2_CLIENT_ID": "953090200888-aoh808jpnni2qp3g64lvb9fm1v50vksc.apps.googleusercontent.com",
    "OAUTH2_CLIENT_SECRET": "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",
    "OAUTH2_META_URL": "https://accounts.google.com/.well-known/openid-configuration",
    "FLASK_SECRET": "ALongRandomlyGeneratedString",
    "FLASK_PORT": 5000
}







url: str = os.environ.get("SUPABASE_URL")
key: str = os.environ.get("SUPABASE_KEY")
supabase: Client = create_client(url, key)

oak = os.environ.get('aiapi')

headers = {
        'Authorization': f'Bearer {oak}'
    }





def render_template(template_name , context = {}):
    file_loader = FileSystemLoader('/Users/max/Desktop/Coding/textsum/stat')
    env = Environment(loader=file_loader)
    template = env.get_template(template_name)
    return template.render(context)





app = Flask(__name__)
oauth = OAuth(app)
oauth.register("mapp" , client_id=appConf.get("OAUTH2_CLIENT_ID"),
    client_secret=appConf.get("OAUTH2_CLIENT_SECRET"),
    client_kwargs={
        "scope": "openid profile email"
        # 'code_challenge_method': 'S256'  # enable PKCE
    },
    server_metadata_url=f'{appConf.get("OAUTH2_META_URL")}',)


app.secret_key = b'parth'


app.config['DEBUG'] = True

login_manager = LoginManager()
login_manager.init_app(app)

login_manager.login_view = '/google-login'

def login_required(f):
    """
    Decorate routes to require login.

    http://flask.pocoo.org/docs/0.12/patterns/viewdecorators/
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user") is None:
            return redirect("/auth")
        return f(*args, **kwargs)
    return decorated_function

@app.route("/google-login")
def googleLogin():
    return oauth.mapp.authorize_redirect(redirect_uri="http://127.0.0.1:5000/signin-google", _external=True)

@app.route("/signin-google")
def googleCallback():
    # fetch access token and id token using authorization code
    token = oauth.mapp.authorize_access_token()
    session['user'] = str(uuid.uuid4())
    return redirect(url_for("index"))

    
    

    

    #return redirect(url_for("index"))
    #return redirect(url_for("index"))

@app.route("/logout")
@login_required
def logout():
    session.pop("user" , None)
    return redirect(url_for("auth"))


@app.route("/auth")
def auth():
    return render_template("login.html")    
    








@app.route('/' , methods = ['POST' , 'GET'])
@login_required
def index():
    if request.method == "GET": 
        return render_template("hp.html")
    else:
    


        reader = PdfReader(request.files['pd'])
        writer = PdfWriter()
        for page in reader.pages:
            writer.add_page(page)

        writer.encrypt(request.form.get('pass'))    

        with open("encrypted-pdf.pdf", "wb") as f:
            writer.write(f)


        page = reader.pages[1]


        po = page.extract_text()
        return render_template('hp.html' , {'p': po})
    
#@app.route('/setp' , methods = ['POST' , 'GET'])
#@login_required
#def setp():
    if request.method == 'POST':
        k = (supabase.table('pass').select('token' , count = 'exact').execute()).json()
        if (json.loads(k))['count'] > 0:
            return "yes"
        else:
            return "no"
        

    else:
        k = supabase.table('pass').select('*').eq('token' , '123').execute()
        m = json.loads(k)
        
        return m


        

        
    
   




    


@app.route('/download')
@login_required
def dload():

    


    headers = {
        'Content-Type': 'application/pdf',
        'Content-Disposition': 'attachment; filename=encrypted-pdf.pdf'
    }

    return send_file('/Users/max/Desktop/Coding/encrypted-pdf.pdf' , as_attachment=  True)

    return redirect(url_for('index'))






    

    




        

            




    
    



     

if __name__ == '__main__': 
    app.run() 
    
