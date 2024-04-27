from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from pymongo import MongoClient
import bcrypt
import requests
from bson.objectid import ObjectId
from flask_cors import CORS

app = Flask(__name__, template_folder='templates')
CORS(app)
app.secret_key = 'your_secret_key'

# Function to connect to MongoDB
def connect_to_mongodb():
    try:
        client = MongoClient("mongodb://localhost:27017/")
        print("Connected to MongoDB")
        return client['Swehul_News_Aggregator']  # Return the database directly
    except Exception as e:
        flash('An error occurred: {}'.format(e), 'danger')
        return None

# Global db variable for database access
db = connect_to_mongodb()
if db is None:
    @app.route('/')
    def handle_db_connection_error():
        flash('Failed to connect to the database.', 'danger')
        return redirect(url_for('login'))

# Function to check if user is logged in
def is_logged_in():
    return 'user_id' in session

# Function to fetch user from database by username
def fetch_user_by_username(username):
    users_collection = db['users']
    user = users_collection.find_one({'username': username})
    return user

# Function to save user data to the database
def save_user_to_database(username, password):
    users_collection = db['users']
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    users_collection.insert_one({'username': username, 'password': hashed_password.decode('utf-8')})

# Function to save article data to the database
def save_article_to_database(title, content, source, user_id):
    articles_collection = db['articles']

    articles_collection.insert_one({'title': title, 'content': content, 'source': source, 'user_id': user_id})

def check_username_available(username):
    users_collection = db['users']  # Access the 'users' collection using dot notation
    user = users_collection.find_one({'username': username})
    return not user

# Homepage route
@app.route('/')
def index():
    api_key = 'fbe4e4dc0f944629b23db0c5f03a210b'
    headlines = get_top_headlines(api_key)
    if headlines:
        return render_template('index.html', headlines=headlines)
    else:
        return "Failed to fetch top headlines."

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Check if a specific page is requested after login
        redirect_to = request.form.get('redirect_to')
        username = request.form['username']
        password = request.form['password']
        user = fetch_user_by_username(username)

        if user and bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
            session['user_id'] = str(user['_id'])
            session['username'] = user['username']
            flash('Logged in successfully!', 'success')
            
            # Redirect based on user action before login
            if redirect_to == 'user_articles':
                return redirect(url_for('user_articles'))
            else:
                return redirect(url_for('index'))  # Redirect to homepage

        else:
            flash('Invalid username or password.', 'danger')
            return redirect(url_for('login'))
    else:
        return render_template('login_singup.html')

# Signup route
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if check_username_available(username):
            save_user_to_database(username, password)
            flash('You have successfully signed up! Please log in.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Username is not available. Please choose another one.', 'danger')
            return redirect(url_for('signup'))
    else:
        return render_template('signup.html')

# Logout route
@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully!', 'success')
    return redirect(url_for('index'))

# SwehulYoutube route
@app.route('/SwehulYoutube')
def swehul_youtube():
    return render_template('SwehulYoutube.html')

# Update the existing 'articles' route to render user-specific articles
@app.route('/user_articles')
def user_articles():
    if is_logged_in():
        user_id = session.get('user_id')
        if user_id:
            articles_collection = db['articles']
            user_articles = articles_collection.find({'user_id': user_id})
            return render_template('user_articles.html', user_articles=user_articles)
        else:
            flash('User ID not found in session. Please log in again.', 'danger')
            return redirect(url_for('login'))
    else:
        flash('You need to login first to view articles.', 'danger')
        return redirect(url_for('login'))

# Article Detail Page route
@app.route('/article/<article_id>')
def article_detail(article_id):
    articles_collection = db['articles']
    article = articles_collection.find_one({'_id': ObjectId(article_id)})

    if article:
        return render_template('article_detail.html', article=article)
    else:
        return "Article not found."

# Articles route
@app.route('/articles', methods=['GET', 'POST'])
def articles():
    if is_logged_in():
        if request.method == 'POST':
            # Form data received, save the article to database
            title = request.form['title']
            content = request.form['content']
            source = request.form['source']
            # Session se user ID retrieve karein
            user_id = session.get('user_id')
            if user_id:
                save_article_to_database(title, content, source, user_id)
                flash('Article submitted successfully!', 'success')
                return redirect(url_for('user_articles'))  # Redirect to user_articles page after submitting article
            else:
                flash('User ID not found in session. Please log in again.', 'danger')
                return redirect(url_for('login'))
        else:
            # Check if old content is passed along with the redirect
            old_title = request.args.get('title')
            old_source = request.args.get('source')
            # Render the articles page with the form to submit articles and display old content for editing
            return render_template('articles.html', username=session['username'], old_title=old_title, old_source=old_source)
    else:
        flash('You need to login first to view articles.', 'danger')
        return redirect(url_for('login'))

# Route for handling article submission
@app.route('/submit_article', methods=['POST'])
def submit_article():
    if request.method == 'POST':
        # Form se data retrieve karein
        title = request.form['title']
        content = request.form['content']
        source = request.form['source']
        # Session se user ID retrieve karein
        user_id = session.get('user_id')
        if user_id:
            # Article ko database mein save karein
            save_article_to_database(title, content, source, user_id)
            flash('Article submitted successfully!', 'success')
            # Article submit karne ke baad user_articles route pe redirect karein
            return redirect(url_for('user_articles'))  # user_articles route pe redirect karein
        else:
            flash('User ID not found in session. Please log in again.', 'danger')
            return redirect(url_for('login'))

# PersonalisedGenresSelection route
@app.route('/PersonalisedGenresSelection')
def personalised_genres_selection():
    return render_template('PersonalisedGenresSelection.html')

# Route for viewing and editing a single article
@app.route('/article/<article_id>', methods=['GET', 'POST'])
def article(article_id):
    if is_logged_in():
        # Fetch the article from the databasedb = get_db()
        articles_collection = db['articles']
        article = articles_collection.find_one({'_id': ObjectId(article_id)})
        if article:
            return render_template('article.html', article=article)
        else:
            flash('Article not found.', 'danger')
            return redirect(url_for('articles'))
    else:
        flash('You need to log in first to view and edit articles.', 'danger')
        return redirect(url_for('login'))

# Function to fetch articles from database
def fetch_articles_from_database():
    articles_collection = db['articles']
    articles = articles_collection.find()
    return articles

def is_admin():
    return 'username' in session and session['username'] == 'admin'

def is_author(article_id):
    articles_collection = db['articles']
    article = articles_collection.find_one({'_id': ObjectId(article_id)})
    if article:
        return 'username' in session and str(session['user_id']) == str(article['user_id'])
    return False

# Update the delete_article route to handle database deletion and provide detailed error messages
@app.route('/delete_article/<article_id>', methods=['POST'])
def delete_article(article_id):
    if is_logged_in():
        if is_admin() or is_author(article_id):
            try:
                articles_collection = db['articles']
                articles_collection.delete_one({'_id': ObjectId(article_id)})
                return jsonify({'success': True})
            except Exception as e:
                print(e)  # Print the error for debugging
                return jsonify({'success': False, 'error': 'An error occurred while deleting the article.'})
        else:
            return jsonify({'success': False, 'error': 'You are not authorized to delete this article.'})
    else:
        return jsonify({'success': False, 'error': 'You need to be logged in to delete articles.'})

# Update the edit_article function to include the print statement
# Edit article route
@app.route('/edit_article/<article_id>', methods=['GET', 'POST'])
def edit_article(article_id):
    if request.method == 'POST':
        # Form data received, update the article in the database
        title = request.form['title']
        content = request.form['content']
        author = request.form['source']  # Assuming you have an author field in the form
        # Update the article in the database
        update_article_in_database(article_id, title, content, source)
        # Redirect to user's articles page after updating
        return redirect(url_for('user_articles'))
    else:
        # Fetch the existing article data for editing
        article = fetch_article_by_id(article_id)
        if article:
            return render_template('edit_article.html', article=article)
        else:
            flash('Article not found.', 'danger')
            return redirect(url_for('user_articles'))


def update_article_in_database(article_id, title, content, author):
    # Assuming you have a database connection and article collection
    articles_collection.update_one(
        {'_id': ObjectId(article_id)},
        {'$set': {'title': title, 'content': content, 'author': author}}
    )



# Function to fetch top headlines from News API
def get_top_headlines(api_key):
    url = 'https://newsapi.org/v2/top-headlines'
    params = {
        'apiKey': api_key,
        'country': 'IN'  # Country code as per ISO 3166-1 alpha-2
    }
    response = requests.get(url, params=params)
    data = response.json()
    if data['status'] == 'ok':
        return data['articles']
    else:
        return None

# Function to view users from database
@app.route('/view_users')
def view_users():
    users_collection = db['users']
    users = users_collection.find()
    return render_template('view_users.html', users=users)

# Function to view articles from database
@app.route('/view_articles')
def view_articles():
    articles_collection = db['articles']
    articles = articles_collection.find()
    return render_template('view_articles.html', articles=articles)

if __name__ == '__main__':
    app.run(debug=True)
