import pytesseract
from flask import Flask, request, jsonify, render_template, redirect, url_for, flash, send_file, session
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from itsdangerous import URLSafeTimedSerializer
from flask_mail import Mail, Message
from flask_wtf import CSRFProtect
from flask_security import Security, SQLAlchemyUserDatastore, UserMixin, RoleMixin, login_required, current_user, login_user, logout_user, hash_password, verify_password
from transformers import pipeline
import aiohttp
import asyncio
import re
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import phonenumbers
from PIL import Image
from io import BytesIO
import os
from dotenv import load_dotenv
import logging
import requests
import json  # Import json module for serialization
import csv  # Import csv module for CSV generation
from io import StringIO
import tempfile  # Import tempfile module for temporary file creation
import uuid
from flask_wtf.csrf import CSRFProtect


# Load API keys from .env file
load_dotenv()
GOOGLE_PLACES_API_KEY = os.getenv("GOOGLE_PLACES_API_KEY")
GOOGLE_GEOCODING_API_KEY = os.getenv("GOOGLE_GEOCODING_API_KEY")
GOOGLE_PLACE_DETAILS_API_URL = "https://maps.googleapis.com/maps/api/place/details/json"
GOOGLE_PLACES_API_URL = "https://maps.googleapis.com/maps/api/place/textsearch/json"
GOOGLE_GEOCODING_API_URL = "https://maps.googleapis.com/maps/api/geocode/json"


# DB_HOST = 'localhost'
# DB_PORT = '5432'
# DB_NAME = 'miramind_BizFinder'
# DB_USER = 'miramind_root_user'
# DB_PASS = 'O!)EkMLfy9W8'


# # Database configuration
# DATABASE_URL = f'postgresql://{DB_USER}:{DB_PASS}@{DB_HOST}:{DB_PORT}/{DB_NAME}'

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DATABASE_URL = f"sqlite:///{os.path.join(BASE_DIR, 'database.sqlite3')}"


# Estimated cost per API call (in USD)
GEOCODING_API_COST = 0.005  # Example cost for a geocoding API call
PLACES_API_COST = 0.017  # Example cost for a Places API call

# Estimated time per API call (in seconds)
GEOCODING_API_TIME = 0.5  # Example time for a geocoding API call
PLACES_API_TIME = 0.5  # Example time for a Places API call
SCRAPING_TIME = 2  # Example time for scraping each website

app = Flask(__name__)

application = app

csrf = CSRFProtect(app)





app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = '06a93555240fe4d285c485742a8d59290277d58b5cff2536'
app.config['SECURITY_PASSWORD_SALT'] = 'your_password_salt'
app.config['SECURITY_PASSWORD_HASH'] = 'argon2'  # Use Argon2 for password hashing
app.config['SECURITY_RECOVERABLE'] = True  # Enable password recovery
app.config['SECURITY_SEND_PASSWORD_RESET_NOTICE_EMAIL'] = True
app.config['SECURITY_EMAIL_SENDER'] = 'noreply@yourdomain.com'
# app.config['SECURITY_RESET_URL'] = '/reset_password'
# app.config['SECURITY_RESET_PASSWORD_TEMPLATE'] = 'reset_password.html'
# app.config['SECURITY_FORGOT_PASSWORD_TEMPLATE'] = 'security/forgot_password.html'
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = 'wizzy.systems@gmail.com'
app.config['MAIL_PASSWORD'] = 'vslt mysa knoo jine'
app.config['MAIL_DEFAULT_SENDER'] = 'wizzy.systems@gmail.com'
# app.config['SECURITY_EMAIL_SENDER'] = 'wizzy.systems@gmail.com'
app.config['TEMPLATES_AUTO_RELOAD'] = True
app.config['SECURITY_LOGIN_URL'] = '/security-login'
app.config['SECURITY_LOGIN_TEMPLATE'] = 'security/login.html'
app.config['WTF_CSRF_ENABLED'] = True
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"  # Or any other suitable type
# app.config["SESSION_FILE_DIR"] = "/tmp/flask_session"
app.config["SECURITY_LOGOUT_URL"] = "/logout"
app.config["SECURITY_POST_LOGOUT_VIEW"] = "/login"
# app.config["SECURITY_POST_LOGIN_VIEW"] = "/home"


db = SQLAlchemy(app)
migrate = Migrate(app, db)  # Initialize Flask-Migrate
csrf = CSRFProtect(app)
mail = Mail(app)
s = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# Define models for Flask-Security
roles_users = db.Table('roles_users',
    db.Column('user_id', db.Integer(), db.ForeignKey('account.id')),
    db.Column('role_id', db.Integer(), db.ForeignKey('role.id'))
)

class Role(RoleMixin, db.Model):
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(80), unique=True)
    description = db.Column(db.String(255))

class User(UserMixin, db.Model):
    __tablename__ = 'account'  # Change table name to 'account'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    active = db.Column(db.Boolean(), default=True)
    confirmed_at = db.Column(db.DateTime())
    reset_token = db.Column(db.String(255), nullable=True)
    fs_uniquifier = db.Column(db.String(64), unique=True, nullable=False, default=lambda: str(uuid.uuid4()))
    roles = db.relationship('Role', secondary=roles_users, backref=db.backref('users', lazy='dynamic'))

class Business(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    website = db.Column(db.String(255), nullable=True)
    phone_numbers = db.Column(db.Text, nullable=True)  # Store as JSON string
    emails = db.Column(db.Text, nullable=True)  # Store as JSON string
    place_id = db.Column(db.String(255), nullable=False)
    business_type = db.Column(db.String(255), nullable=False)
    location = db.Column(db.String(255), nullable=False)
    num_businesses = db.Column(db.Integer, nullable=False)
    search_area = db.Column(db.Integer, nullable=False)

# Setup Flask-Security
user_datastore = SQLAlchemyUserDatastore(db, User, Role)
security = Security(app, user_datastore)


@app.before_request
def before_request():
    print(f"Current User: {current_user}")



@app.route("/", methods=["GET"])
def home():
    return render_template("index.html")

@app.route("/search", methods=["GET"])
@login_required
def search():
    app.logger.debug("Accessing /search with user: %s", current_user)
    return render_template("search_business.html", name=current_user.name)


import logging
logging.basicConfig(level=logging.DEBUG)

@app.route("/login", methods=["GET", "POST"])
def login():
    try:
        if request.method == "POST":
            email = request.form.get("email")
            password = request.form.get("password")
            user = user_datastore.find_user(email=email)

            if user and verify_password(password, user.password):
                login_user(user)
                return redirect(url_for("search"))
            else:
                flash("Invalid email or password.", "danger")  # This shows the error message
    except Exception as e:
        app.logger.error(f"Error during login: {e}")
        flash("An error occurred during login.", "danger")

    return render_template("security/login.html")


@app.route('/forgot_password')
def forgot_password():
    return render_template('forgot_password.html')

import logging
logging.basicConfig(level=logging.DEBUG)





@app.route('/reset_password', methods=["GET", "POST"])
def reset_password_request():
    print("Entered reset_password_request route")  # Debug log
    if request.method == "POST":
        email = request.form.get("email")
        print(f"Email received: {email}")  # Debug log
        user = user_datastore.find_user(email=email)
        if user:
            token = generate_token(email)
            user.reset_token = token
            db.session.commit()
            print(f"Token generated for user {user.email}")  # Debug log
            send_reset_email(user.email, token)
            flash("A password reset link has been sent to your email. Reset and login!", "success")
        else:
            print("Email not found.")  # Debug log
            flash("Email not found in our records.", "danger")
        return redirect(url_for("login"))
    return render_template("security/forgot_password.html")



@app.route('/reset_password/<token>', methods=["GET", "POST"])
def reset_password(token):
    user = User.query.filter_by(reset_token=token).first()
    if not user:
        flash("Invalid or expired token.", "danger")
        return redirect(url_for("reset_password_request"))

    if request.method == "POST":
        password = request.form.get("password")
        password_confirm = request.form.get("password_confirm")
        if len(password) < 6:
            flash("Password must be at least 6 characters long.", "danger")
            return render_template("security/reset_password.html", token=token)
        
        if password != password_confirm:
            flash("Passwords do not match.", "danger")
            return render_template("security/reset_password.html", token=token)

        user.password = hash_password(password)  # Securely hash the new password
        user.reset_token = None  # Invalidate the token
        db.session.commit()
        flash("Your password has been reset successfully. You can now log in.", "success")
        return redirect(url_for("login"))

    return render_template("security/reset_password.html", token=token)


from itsdangerous import URLSafeTimedSerializer

def generate_token(email):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    return serializer.dumps(email, salt=app.config['SECURITY_PASSWORD_SALT'])


def validate_token(token, expiration=3600):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    try:
        email = serializer.loads(
            token,
            salt=app.config['SECURITY_PASSWORD_SALT'],
            max_age=expiration
        )
        return email
    except Exception:
        return None


from flask_mail import Message

def send_reset_email(email, token):
    reset_url = url_for('reset_password', token=token, _external=True)
    
    # HTML content for a professional email design
    html_body = f"""
    <html>
        <head>
            <style>
                body {{
                    font-family: Arial, sans-serif;
                    background-color: #f8f9fa;
                    margin: 0;
                    padding: 0;
                }}
                .email-container {{
                    max-width: 600px;
                    margin: 0 auto;
                    padding: 20px;
                    background-color: #ffffff;
                    border-radius: 8px;
                    box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
                }}
                .email-header {{
                    background-color: #007bff;
                    color: white;
                    padding: 15px;
                    text-align: center;
                    border-radius: 8px 8px 0 0;
                }}
                .email-body {{
                    padding: 20px;
                    font-size: 16px;
                    line-height: 1.5;
                    color: #333333;
                }}
                .btn {{
                    background-color: #007bff;
                    color: white;
                    padding: 12px 20px;
                    text-decoration: none;
                    font-size: 16px;
                    border-radius: 5px;
                    display: inline-block;
                }}
                .footer {{
                    text-align: center;
                    color: #888888;
                    font-size: 12px;
                    margin-top: 20px;
                }}
            </style>
        </head>
        <body>
            <div class="email-container">
                <div class="email-header">
                    <h1>Password Reset Request</h1>
                </div>
                <div class="email-body">
                    <p>Hello,</p>
                    <p>We received a request to reset your password. To proceed, please click the button below:</p>
                    <p style="text-align: center;">
                        <a style="color:white;" href="{reset_url}" class="btn">Reset Your Password</a>
                    </p>
                    <p>If you did not request a password reset, please ignore this email.</p>
                    <p>Thank you, <br> The BizFinder Team</p>
                </div>
                <div class="footer">
                    <p>&copy; 2025 BizFinder. All rights reserved.</p>
                </div>
            </div>
        </body>
    </html>
    """
    
    # Create the email message with HTML content
    msg = Message(
        "Password Reset Request",
        recipients=[email],
        html=html_body
    )
    mail.send(msg)








# @app.route('/reset_password/<token>', methods=['GET', 'POST'])
# def reset_with_token(token):
#     logging.info(f"Processing reset token: {token}")
#     try:
#         # Decode the token and get the email
#         email = s.loads(token, salt='email-confirm', max_age=3600)
#         logging.info(f"Decoded email: {email}")
#     except Exception as e:
#         logging.error(f"Token error: {e}")
#         flash('The reset link is invalid or has expired.', 'danger')
#         return redirect(url_for('forgot_password'))

#     if request.method == 'POST':
#         # Handle the form submission for resetting password
#         new_password = request.form['password']
#         user = user_datastore.find_user(email=email)
#         if user:
#             user.password = hash_password(new_password)
#             db.session.commit()
#             flash('Your password has been updated!', 'success')
#             return redirect(url_for('login'))

#     return render_template('reset_password.html', token=token)


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        name = request.form.get("name")
        email = request.form.get("email")
        password = request.form.get("password")

        # Validate password length
        if len(password) < 6:
            flash("Password must be at least 6 characters long.", "danger")
            return render_template("signup.html")

        # Validate email format (basic validation)
        if "@" not in email or "." not in email:
            flash("Invalid email address.", "danger")
            return render_template("signup.html")
        
        # Check if the email already exists in the database
        existing_user = user_datastore.find_user(email=email)
        print(existing_user)
        if existing_user:
            flash("An account with this email already exists.", "danger")
            return render_template("signup.html")

        hashed_password = hash_password(password)
        user = user_datastore.create_user(name=name, email=email, password=hashed_password)
        db.session.commit()
        login_user(user)
        return redirect(url_for("home"))
    
    return render_template("signup.html")




@app.route("/logout")
@login_required
def logout():
    logout_user()  # Logs out the user
    session.clear()  # Clears Flask session data
    response = redirect(url_for("login"))
    response.set_cookie("session", "", expires=0)  # Expire session cookie
    flash("You have been logged out.", "info")
    return response


async def fetch_website_content(session, url):
    """
    Fetch website content using requests or APIs.
    """
    if url.startswith('javascript:'):
        logging.info(f"Skipping JavaScript URL: {url}")
        return None

    try:
        async with session.get(url) as response:
            if response.status == 200:
                return await response.text()
            else:
                logging.error(f"Failed to fetch content from {url} with status code {response.status}")
                return None
    except Exception as e:
        logging.error(f"Error fetching website content: {e}")
        return None

async def extract_text_from_image(session, image_url):
    """
    Extract text from an image using OCR.
    """
    if image_url.startswith('data:image'):
        logging.info(f"Skipping base64-encoded image: {image_url[:30]}...")
        return ""
    if image_url.endswith('.svg'):
        logging.info(f"Skipping SVG image: {image_url}")
        return ""
    
    try:
        async with session.get(image_url) as response:
            img = Image.open(BytesIO(await response.read()))
            text = pytesseract.image_to_string(img)
            return text
    except Exception as e:
        logging.error(f"Error extracting text from image: {e}")
        return ""

def extract_contacts(text):
    """
    Use NLP to extract potential contact information from text.
    """
    contacts = {"emails": [], "phone_numbers": []}

    # Regular expressions for email detection
    email_regex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'

    # Find all matches for emails
    emails = re.findall(email_regex, text)
    contacts["emails"].extend(emails)

    # Find all potential phone numbers
    potential_phone_numbers = re.findall(r'\+?\d[\d\s\-\(\)]{8,}\d', text)
    for number in potential_phone_numbers:
        try:
            parsed_number = phonenumbers.parse(number, "US")  # Assuming US region for parsing
            if phonenumbers.is_valid_number(parsed_number):
                formatted_number = phonenumbers.format_number(parsed_number, phonenumbers.PhoneNumberFormat.E164)
                contacts["phone_numbers"].append(formatted_number)
        except phonenumbers.NumberParseException:
            continue
    
    # Remove duplicates
    contacts["emails"] = list(set(contacts["emails"]))
    contacts["phone_numbers"] = list(set(contacts["phone_numbers"]))
    return contacts

async def crawl_website(session, url, max_pages=5):
    """
    Crawl the website to fetch content from multiple pages.
    """
    visited_urls = set()
    urls_to_visit = [url]
    all_contacts = {"emails": [], "phone_numbers": []}

    while urls_to_visit and len(visited_urls) < max_pages:
        current_url = urls_to_visit.pop(0)
        if current_url in visited_urls or current_url.startswith('javascript:'):
            continue

        logging.info(f"Crawling URL: {current_url}")
        content = await fetch_website_content(session, current_url)
        if not content:
            continue

        contacts = extract_contacts(content)
        all_contacts["emails"].extend(contacts["emails"])
        all_contacts["phone_numbers"].extend(contacts["phone_numbers"])

        visited_urls.add(current_url)

        soup = BeautifulSoup(content, 'html.parser')
        for img in soup.find_all('img', src=True):
            image_url = urljoin(current_url, img['src'])
            image_text = await extract_text_from_image(session, image_url)
            image_contacts = extract_contacts(image_text)
            all_contacts["emails"].extend(image_contacts["emails"])
            all_contacts["phone_numbers"].extend(image_contacts["phone_numbers"])

        for link in soup.find_all('a', href=True):
            absolute_url = urljoin(current_url, link['href'])
            if absolute_url not in visited_urls and absolute_url not in urls_to_visit and not absolute_url.startswith('javascript:'):
                urls_to_visit.append(absolute_url)

    # Remove duplicates
    all_contacts["emails"] = list(set(all_contacts["emails"]))
    all_contacts["phone_numbers"] = list(set(all_contacts["phone_numbers"]))
    return all_contacts

async def additional_scraping(session, url, existing_contacts, max_pages=5):
    """
    Perform additional scraping to find more contacts.
    """
    visited_urls = set()
    urls_to_visit = [url]
    new_contacts = {"emails": [], "phone_numbers": []}

    while urls_to_visit and len(visited_urls) < max_pages:
        current_url = urls_to_visit.pop(0)
        if current_url in visited_urls or current_url.startswith('javascript:'):
            continue

        logging.info(f"Additional scraping URL: {current_url}")
        content = await fetch_website_content(session, current_url)
        if not content:
            continue

        contacts = extract_contacts(content)
        for email in contacts["emails"]:
            if email not in existing_contacts["emails"]:
                new_contacts["emails"].append(email)
                existing_contacts["emails"].append(email)
        for phone_number in contacts["phone_numbers"]:
            if phone_number not in existing_contacts["phone_numbers"]:
                new_contacts["phone_numbers"].append(phone_number)
                existing_contacts["phone_numbers"].append(phone_number)

        visited_urls.add(current_url)

        soup = BeautifulSoup(content, 'html.parser')
        for img in soup.find_all('img', src=True):
            image_url = urljoin(current_url, img['src'])
            image_text = await extract_text_from_image(session, image_url)
            image_contacts = extract_contacts(image_text)
            for email in image_contacts["emails"]:
                if email not in existing_contacts["emails"]:
                    new_contacts["emails"].append(email)
                    existing_contacts["emails"].append(email)
            for phone_number in image_contacts["phone_numbers"]:
                if phone_number not in existing_contacts["phone_numbers"]:
                    new_contacts["phone_numbers"].append(phone_number)
                    existing_contacts["phone_numbers"].append(phone_number)

        for link in soup.find_all('a', href=True):
            absolute_url = urljoin(current_url, link['href'])
            if absolute_url not in visited_urls and absolute_url not in urls_to_visit and not absolute_url.startswith('javascript:'):
                urls_to_visit.append(absolute_url)

    return new_contacts

async def google_maps_search(session, query, lat, lon, radius):
    params = {
        'query': query,
        'location': f'{lat},{lon}',
        'radius': radius * 1609.34,  # Convert miles to meters
        'key': GOOGLE_PLACES_API_KEY
    }
    try:
        logging.info(f"Searching Google Maps for query: {query} at location: {lat},{lon} with radius: {radius} miles")
        async with session.get(GOOGLE_PLACES_API_URL, params=params) as response:
            response.raise_for_status()
            results = await response.json()
            return results.get('results', [])
    except Exception as e:
        logging.error(f"Failed to search Google Maps: {e}")
        return []

async def get_place_details(session, place_id):
    params = {
        'place_id': place_id,
        'key': GOOGLE_PLACES_API_KEY
    }
    try:
        logging.info(f"Fetching place details for place_id: {place_id}")
        async with session.get(GOOGLE_PLACE_DETAILS_API_URL, params=params) as response:
            response.raise_for_status()
            result = await response.json()
            return result.get('result', {})
    except Exception as e:
        logging.error(f"Failed to retrieve place details: {e}")
        return {}

def generate_grid_coordinates(lat, lon, area):
    grid_cell_size = 1  # miles

    # Convert grid cell size to degrees
    grid_cell_lat = grid_cell_size / 69.0  # 1 degree latitude ~ 69 miles
    grid_cell_lon = grid_cell_size / 55.0  # 1 degree longitude ~ 55 miles at mid-latitudes

    # Estimate bounds (these should be replaced with real bounds if available)
    north = lat + (area**0.5 / 69.0) / 2
    south = lat - (area**0.5 / 69.0) / 2
    east = lon + (area**0.5 / 55.0) / 2
    west = lon - (area**0.5 / 55.0) / 2

    coordinates = []
    current_lat = south
    while current_lat <= north:
        current_lon = west
        while current_lon <= east:
            coordinates.append((current_lat, current_lon))
            current_lon += grid_cell_lon
        current_lat += grid_cell_lat
    
    return coordinates

def get_coordinates(location, area):
    params = {
        'address': location,
        'key': GOOGLE_GEOCODING_API_KEY
    }
    try:
        logging.info(f"Geocoding location: {location}")
        response = requests.get(GOOGLE_GEOCODING_API_URL, params=params)
        response.raise_for_status()
        location_data = response.json().get('results', [])[0]['geometry']['location']
        lat = location_data['lat']
        lon = location_data['lng']
        return generate_grid_coordinates(lat, lon, area), len(generate_grid_coordinates(lat, lon, area))
    except requests.RequestException as e:
        logging.error(f"Could not geocode location: {location} - {e}")
        return [], 0

@app.route("/search_business", methods=["POST"])
@login_required
async def search_business():
    data = request.json
    query = data.get("query")
    location = data.get("location")
    num_businesses = int(data.get("num_businesses", 10))  # Default to 10 businesses if not specified
    search_area = int(data.get("search_area", 1))  # Default to 1 mile if not specified
    if not query or not location:
        return jsonify({"error": "Query, location, number of businesses, and search area are required."})

    coordinates, _ = get_coordinates(location, search_area)
    businesses = []
    total_cost = 0
    total_time = 0

    async with aiohttp.ClientSession() as session:
        for lat, lon in coordinates:
            print(f"Searching at coordinates: {lat}, {lon}")
            search_results = await google_maps_search(session, query, lat, lon, search_area)
            for result in search_results:
                if len(businesses) >= num_businesses:
                    break
                place_id = result['place_id']
                details = await get_place_details(session, place_id)
                business_name = details.get('name')
                website = details.get('website')
                phone_number = details.get('formatted_phone_number')
                
                if business_name == "N/A":
                    continue  # Skip businesses with name "N/A"

                if website:
                    contacts = await crawl_website(session, website)
                    emails = contacts["emails"]
                    phone_numbers = contacts["phone_numbers"]
                    total_time += SCRAPING_TIME
                else:
                    emails = []
                    phone_numbers = []

                total_cost += PLACES_API_COST
                total_time += PLACES_API_TIME

                # Save business to database
                business = Business(
                    name=business_name,
                    website=website or "N/A",
                    phone_numbers=json.dumps(phone_numbers),  # Serialize to JSON string
                    emails=json.dumps(emails),  # Serialize to JSON string
                    place_id=place_id,
                    business_type=query,
                    location=location,
                    num_businesses=num_businesses,
                    search_area=search_area
                )
                db.session.add(business)
                db.session.commit()

                businesses.append({
                    'Business Name': business_name,
                    'Website': website or "N/A",
                    'Phone Numbers': phone_number or "N/A",
                    'Emails': ', '.join(emails) or "N/A",
                    'Place ID': place_id
                })

            if len(businesses) >= num_businesses:
                break

        # Perform additional scraping to find more contacts
        for business in businesses:
            if business['Website'] != "N/A":
                new_contacts = await additional_scraping(session, business['Website'], contacts)
                business['Emails'] += ', '.join(new_contacts["emails"])
                business['Phone Numbers'] += ', '.join(new_contacts["phone_numbers"])

    # Create a CSV file
    with tempfile.NamedTemporaryFile(delete=False, mode='w', encoding='utf-8', suffix='.csv') as csv_file:
        csv_writer = csv.writer(csv_file)
        csv_writer.writerow(['Business Name', 'Website', 'Phone Numbers', 'Emails', 'Place ID'])

        for business in businesses:
            csv_writer.writerow([
                business['Business Name'],
                business['Website'],
                business['Phone Numbers'],
                business['Emails'],
                business['Place ID']
            ])

    return jsonify({
        "businesses": businesses,
        "total_cost": total_cost,
        "total_time": total_time,
        "csv_filename": csv_file.name
    })

@app.route("/download_csv", methods=["POST"])
def download_csv():
    data = request.json
    csv_filename = data.get("csv_filename")

    return send_file(
        csv_filename,
        mimetype='text/csv',
        download_name='businesses.csv',
        as_attachment=True
    )

if __name__ == "__main__":
    app.run(debug=True)