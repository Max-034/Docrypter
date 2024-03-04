from flask import Flask, request, jsonify , send_file , url_for , redirect , session
import os , json , io ,base64
from supabase import create_client, Client
from PyPDF2 import PdfReader , PdfWriter
from authlib.integrations.flask_client import OAuth
import google.oauth2.credentials
import google_auth_oauthlib.flow
from jinja2 import Environment, FileSystemLoader
import code
from oauthlib.oauth2 import WebApplicationClient
import requests
from functools import wraps
from werkzeug.security import check_password_hash, generate_password_hash
import uuid
import supabase
from io import BytesIO


# from flask_login import (
#     LoginManager,
#     current_user,
#     login_required,
#     login_user,
#     logout_user,
# )

url: str = os.environ.get("SURL")
key: str = os.environ.get("SKEY")
supabase: Client = create_client(url, key)


appConf = {
    "OAUTH2_CLIENT_ID": "953090200888-aoh808jpnni2qp3g64lvb9fm1v50vksc.apps.googleusercontent.com",
    "OAUTH2_CLIENT_SECRET": "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",
    "OAUTH2_META_URL": "https://accounts.google.com/.well-known/openid-configuration",
    "FLASK_SECRET": "ALongRandomlyGeneratedString",
    "FLASK_PORT": 5000
}

# def render_template(template_name , context = {}):
#     file_loader = FileSystemLoader('textsum/templates')
#     env = Environment(loader=file_loader)
#     template = env.get_template(template_name)
#     return template.render(context)

app = Flask(__name__ , template_folder='templates')
oauth = OAuth(app)
oauth.register("mapp" , client_id=appConf.get("OAUTH2_CLIENT_ID"),
    client_secret=appConf.get("OAUTH2_CLIENT_SECRET"),
    client_kwargs={
        "scope": "openid profile email"
    },
    server_metadata_url=f'{appConf.get("OAUTH2_META_URL")}',)


app.secret_key = b'parth'


app.config['DEBUG'] = True

# login_manager = LoginManager()
# login_manager.init_app(app)

# login_manager.login_view = '/google-login'

def login_required(f):
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
    token = oauth.mapp.authorize_access_token()
    session['user'] = str(uuid.uuid4())
    return redirect(url_for("index"))

    
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
        if request.files['pd'] and request.form.get('pass'):

            reader = PdfReader(request.files['pd'])
            writer = PdfWriter()
            for page in reader.pages:
                 writer.add_page(page)

            writer.encrypt(request.form.get('pass')) 

            binary_variable = io.BytesIO()
            binary_variable.seek(0)   
            writer.write(binary_variable)
            binary_variable = binary_variable.getvalue()

            base64_data = base64.b64encode(binary_variable).decode()

 # Create a JSON object with binary data as Base64 string
            json_data = {"binary_data": base64_data}

# Convert JSON object to JSON string
            json_string = json.dumps(json_data)


            data, count = supabase.table('pdf').insert({"pdf": json_string ,"text": session.get('user') }).execute()
            
   

            #with open("encrypted-pdf.pdf", "wb") as f:
            #    writer.write(f)


            page = reader.pages[1]
            po = page.extract_text()
            return render_template('hp.html' , {'p': po})
        
        else:
            return redirect(url_for("index"))
        

    

@app.route('/download')
@login_required
def dload():    
    headers = {
        'Content-Type': 'application/pdf',
        'Content-Disposition': 'attachment; filename=encrypted-pdf.pdf'
    }


    response = supabase.table('pdf').select('pdf').eq('text' , session.get('user')).execute()
    data, count = supabase.table('pdf').delete().eq('text', session.get('user')).execute()

    k = (response.data[0]["pdf"])[17:-2]


    binary_data = base64.b64decode(k)

    bd = BytesIO(binary_data)
    bd.seek(0)

    return send_file(bd , as_attachment=  True , mimetype="application/pdf" , download_name="downloaded_pdf.pdf" )

    return redirect(url_for('index'))
            
if __name__ == '__main__': 
    app.run() 
    
