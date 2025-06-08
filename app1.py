import bcrypt
from flask import Flask, request, jsonify
from flask_mysqldb import MySQL
from datetime import datetime, timedelta
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, get_jwt
from flask_cors import CORS
from flask_bcrypt import Bcrypt
import os
from werkzeug.utils import secure_filename

app = Flask(__name__, static_url_path='/static',static_folder='static')

# Configuration
app.config['MYSQL_USER'] = "root"
app.config['MYSQL_PASSWORD'] = "root"
app.config['MYSQL_DB'] = "ems"
app.config['MYSQL_HOST'] = "localhost"
app.config['JWT_SECRET_KEY'] = 'your-very-secure-secret-key'
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}

# Ensure upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

mysql = MySQL(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
CORS(app)

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

# Temporary endpoint to create a default admin (remove after use)
@app.route('/setup-admin', methods=['POST'])
def setup_admin():
    try:
        # Default values
        default_username = 'admin'
        default_email = 'admin123@gmail.com'
        default_password = 'admin123'

        # Get data from request or use default
        data = request.get_json() or {}
        admin_name = data.get('username', default_username)
        email = data.get('email', default_email)
        password = data.get('password', default_password)

        if not email or not password:
            return jsonify({"error": "email and password are required"}), 400

        cursor = mysql.connection.cursor()
        cursor.execute("SELECT email FROM admins WHERE email = %s", (email,))
        if cursor.fetchone():
            cursor.close()
            return jsonify({"error": "Admin already exists"}), 409

        # Hash the password 
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        # Insert admin record
        cursor.execute(
            "INSERT INTO admins (admin_name, email, password) VALUES (%s, %s, %s)",
            (admin_name, email, hashed_password)
        )
        mysql.connection.commit()
        cursor.close()

        return jsonify({"message": "Admin created successfully"}), 201

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.json
        email = data.get('email')
        password = data.get('password')
        role = data.get('role')  # 'user' or 'admin'

        if role not in ['user', 'admin']:
            return jsonify({"error": "Invalid role specified"}), 400

        cursor = mysql.connection.cursor()
        user = None
        user_id = None
        stored_password = None

        if role == 'user':
            cursor.execute("SELECT user_id, user_name, user_email, password FROM users WHERE user_email = %s", (email,))
            user = cursor.fetchone()
            if user:
                user_id, user_name, user_email, stored_password = user

        elif role == 'admin':
            cursor.execute("SELECT id, admin_name, email, password FROM admins WHERE email = %s", (email,))
            user = cursor.fetchone()
            if user:
                user_id, user_name, user_email, stored_password = user
        cursor.close()

        # Verify username and password
        if not user or not bcrypt.check_password_hash(stored_password, password):
            return jsonify({"error": "Invalid credentials"}), 401

        token = create_access_token(
            identity=str(user_id),
            additional_claims={"role": role},
            expires_delta=timedelta(hours=3)
        )
        return jsonify({
            "message": "Login successful",
            "token": token,
            "role": role,
            "id": user_id
        }), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/register', methods=['POST'])
def register_user():
    try:
        data = request.get_json()
        user_name = data.get('user_name')
        user_email = data.get('user_email')
        password = data.get('password')

        if not all([user_name, user_email, password]):
            return jsonify({"error": "All fields are required"}), 400

        cursor = mysql.connection.cursor()
        
        # Check if email already exists
        cursor.execute("SELECT * FROM users WHERE user_email = %s", (user_email,))
        if cursor.fetchone():
            cursor.close()
            return jsonify({"error": "Email already registered"}), 409

        # Hash the password
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        # Insert into database
        cursor.execute(
            "INSERT INTO users (user_name, user_email, password) VALUES (%s, %s, %s)",
            (user_name, user_email, hashed_password)
        )
        mysql.connection.commit()
        cursor.close()

        return jsonify({"message": "User registered successfully"}), 201

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/admin/add-event', methods=['POST'])
@jwt_required()
def add_event():
    claims = get_jwt()
    if claims.get("role") != "admin":
        return jsonify({"error": "Admins only"}), 403

    try:
        # Handle form data
        event_name = request.form.get('event_name')
        category = request.form.get('category')
        event_description = request.form.get('event_description')
        rules = request.form.get('rules')
        event_date = request.form.get('event_date')
        event_time = request.form.get('event_time')
        venue = request.form.get('venue')

        if not all([event_name, category, event_description, rules, event_date, event_time, venue]):
            return jsonify({"error": "All fields are required"}), 400

        # Convert date and time formats
        dateformat = datetime.strptime(event_date, '%Y-%m-%d').date()
        timeformat = datetime.strptime(event_time, '%H:%M').time()

        # Handle file upload
        image_path = None
        # In the add_event endpoint, modify the image handling:
        if 'event_image' in request.files:
            file = request.files['event_image']
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            image_path = os.path.join('/uploads', filename)  # Store relative path

        cursor = mysql.connection.cursor()
        cursor.execute("""
            INSERT INTO events (event_name, category, event_description, rules, 
                               event_date, event_time, venue, image_path)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """, (event_name, category, event_description, rules, 
              dateformat, timeformat, venue, image_path))
        mysql.connection.commit()
        cursor.close()

        return jsonify({"message": "Event added successfully"}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/admin/update-event/<int:event_id>', methods=['PUT'])
@jwt_required()
def update_event(event_id):
    claims = get_jwt()
    if claims.get("role") != "admin":
        return jsonify({"error": "Admins only"}), 403

    try:
        # Initialize image_path as None
        image_path = None
        
        # Handle file upload if present
        if 'event_image' in request.files:
            file = request.files['event_image']
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)
                image_path = os.path.join('/uploads', filename)

        # Get other form data
        event_name = request.form.get('event_name')
        category = request.form.get('category')
        event_description = request.form.get('event_description')
        rules = request.form.get('rules')
        event_date = request.form.get('event_date')
        event_time = request.form.get('event_time')
        venue = request.form.get('venue')

        if not all([event_name, category, event_description, rules, event_date, event_time, venue]):
            return jsonify({"error": "All fields are required"}), 400

        # Convert date and time formats
        dateformat = datetime.strptime(event_date, '%Y-%m-%d').date()
        timeformat = datetime.strptime(event_time, '%H:%M').time()

        cursor = mysql.connection.cursor()
        
        if image_path:
            # Update with new image
            cursor.execute("""
                UPDATE events
                SET event_name = %s,
                    category = %s,
                    event_description = %s,
                    rules = %s,
                    event_date = %s,
                    event_time = %s,
                    venue = %s,
                    image_path = %s
                WHERE event_id = %s
            """, (event_name, category, event_description, rules, 
                  dateformat, timeformat, venue, image_path, event_id))
        else:
            # Update without changing image
            cursor.execute("""
                UPDATE events
                SET event_name = %s,
                    category = %s,
                    event_description = %s,
                    rules = %s,
                    event_date = %s,
                    event_time = %s,
                    venue = %s
                WHERE event_id = %s
            """, (event_name, category, event_description, rules, 
                  dateformat, timeformat, venue, event_id))
        
        mysql.connection.commit()
        cursor.close()

        return jsonify({"message": "Event updated successfully"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
@app.route('/admin/delete-event/<int:event_id>', methods=['DELETE'])
@jwt_required()
def delete_event(event_id):
    claims = get_jwt()
    if claims.get("role") != "admin":
        return jsonify({"error": "Admins only"}), 403

    try:
        cursor = mysql.connection.cursor()
        
        # First get image path to delete the file
        cursor.execute("SELECT image_path FROM events WHERE event_id = %s", (event_id,))
        result = cursor.fetchone()
        if result and result[0]:
            try:
                os.remove(result[0])
            except:
                pass
        
        # Then delete the event
        cursor.execute("DELETE FROM events WHERE event_id = %s", (event_id,))
        mysql.connection.commit()
        cursor.close()

        return jsonify({"message": "Event deleted successfully"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/admin/view-all-events', methods=['GET'])
@jwt_required()
def view_all_events():
    claims = get_jwt()
    if claims.get("role") != "admin":
        return jsonify({"error": "Admins only"}), 403

    try:
        cur = mysql.connection.cursor()
        cur.execute("""
            SELECT event_id, event_name, category, event_description, 
                   rules, event_date, event_time, venue, image_path 
            FROM events
        """)
        rows = cur.fetchall()
        cur.close()

        events = []
        for row in rows:
         # In all endpoints that return event data, ensure time is formatted consistently:
# For example in view_all_events:
            events.append({
                "event_id": row[0],
                "event_name": row[1],
                "category": row[2],
                "event_description": row[3],
                "rules": row[4],
                "event_date": str(row[5]),
                "event_time": str(row[6]).rsplit(':', 1)[0],  # Remove seconds if present
                "venue": row[7],
                "image_path": row[8]
            })
        return jsonify({"events": events}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/admin/delete-participant', methods=['DELETE'])
@jwt_required()
def admin_delete_participant():
    claims = get_jwt()
    if claims.get("role") != "admin":
        return jsonify({"error": "Admins only"}), 403

    data = request.get_json()
    user_id = data.get("user_id")
    event_id = data.get("event_id")

    if not user_id or not event_id:
        return jsonify({"error": "user_id and event_id are required"}), 400

    try:
        cur = mysql.connection.cursor()
        cur.execute("DELETE FROM participants WHERE user_id = %s AND event_id = %s", (user_id, event_id))
        mysql.connection.commit()
        row_count = cur.rowcount
        cur.close()

        if row_count == 0:
            return jsonify({"error": "No participant found for given user and event"}), 404

        return jsonify({"message": "Participant deleted successfully"}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/admin/view-participants', methods=['POST'])
@jwt_required()
def view_event_participants():
    claims = get_jwt()
    if claims.get("role") != "admin":
        return jsonify({"error": "Admins only"}), 403

    data = request.get_json()
    event_id = data.get("event_id")

    if not event_id:
        return jsonify({"error": "event_id is required"}), 400

    try:
        cur = mysql.connection.cursor()
        cur.execute("SELECT user_id, user_name FROM participants WHERE event_id = %s", (event_id,))
        rows = cur.fetchall()
        cur.close()

        if not rows:
            return jsonify({"message": "No participants found for this event"}), 200

        participants = []
        for row in rows:
            participants.append({
                "user_id": row[0],
                "user_name": row[1]
            })

        return jsonify({
            "event_id": event_id,
            "participants": participants
        }), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/admin/view-events-by-category', methods=['GET'])
@jwt_required()
def view_events_by_category():
    claims = get_jwt()
    if claims.get("role") != "admin":
        return jsonify({"error": "Admins only"}), 403

    data = request.get_json()
    category = data.get("category")

    if not category:
        return jsonify({"error": "Category is required"}), 400

    try:
        cur = mysql.connection.cursor()
        cur.execute("""
            SELECT event_id, event_name, category, event_description, 
                   rules, event_date, event_time, venue, image_path
            FROM events
            WHERE category = %s
        """, (category,))
        rows = cur.fetchall()
        cur.close()

        events = []
        for row in rows:
           # In all endpoints that return event data, ensure time is formatted consistently:
# For example in view_all_events:
            events.append({
                "event_id": row[0],
                "event_name": row[1],
                "category": row[2],
                "event_description": row[3],
                "rules": row[4],
                "event_date": str(row[5]),
                "event_time": str(row[6]).rsplit(':', 1)[0],  # Remove seconds if present
                "venue": row[7],
                "image_path": row[8]
            })
        if not events:
            return jsonify({"message": f"No events found under category '{category}'"}), 200

        return jsonify({"category": category, "events": events}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/user/view-events', methods=['GET'])
@jwt_required()
def user_view_events():
    claims = get_jwt()
    if claims.get("role") != "user":
        return jsonify({"error": "Users only"}), 403

    try:
        cur = mysql.connection.cursor()
        cur.execute("""
            SELECT event_id, event_name, category, event_description, 
                   rules, event_date, event_time, venue, image_path
            FROM events
        """)
        rows = cur.fetchall()
        cur.close()

        events = []
        for row in rows:
            # In all endpoints that return event data, ensure time is formatted consistently:
# For example in view_all_events:
            events.append({
                "event_id": row[0],
                "event_name": row[1],
                "category": row[2],
                "event_description": row[3],
                "rules": row[4],
                "event_date": str(row[5]),
                "event_time": str(row[6]).rsplit(':', 1)[0],  # Remove seconds if present
                "venue": row[7],
                "image_path": row[8]
            })
        return jsonify({"events": events}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/user/my-events', methods=['GET'])
@jwt_required()
def user_registered_events():
    claims = get_jwt()
    if claims.get("role") != "user":
        return jsonify({"error": "Users only"}), 403

    user_id = int(get_jwt_identity())

    try:
        cur = mysql.connection.cursor()
        
        # Get all events the user has registered for
        cur.execute("""
            SELECT e.event_id, e.event_name, e.category, e.event_description, 
                   e.rules, e.event_date, e.event_time, e.venue, e.image_path
            FROM events e
            JOIN participants p ON e.event_id = p.event_id
            WHERE p.user_id = %s
        """, (user_id,))
        
        rows = cur.fetchall()
        cur.close()

        events = []
        for row in rows:
            events.append({
                "event_id": row[0],
                "event_name": row[1],
                "category": row[2],
                "event_description": row[3],
                "rules": row[4],
                "event_date": str(row[5]),
                "event_time": str(row[6]).rsplit(':', 1)[0],  # Remove seconds if present
                "venue": row[7],
                "image_path": row[8]
            })

        return jsonify({"registered_events": events}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/user/register-event', methods=['POST'])
@jwt_required()
def user_register_event():
    claims = get_jwt()
    if claims.get("role") != "user":
        return jsonify({"error": "Users only"}), 403

    user_id = int(get_jwt_identity())
    data = request.get_json()
    event_id = data.get("event_id")

    if not event_id:
        return jsonify({"error": "Event ID is required"}), 400

    try:
        cur = mysql.connection.cursor()

        # Check if user already registered
        cur.execute("SELECT * FROM participants WHERE user_id = %s AND event_id = %s", (user_id, event_id))
        if cur.fetchone():
            cur.close()
            return jsonify({"error": "Already registered for this event"}), 409

        # Get user_name from users table
        cur.execute("SELECT user_name FROM users WHERE user_id = %s", (user_id,))
        user = cur.fetchone()
        if not user:
            cur.close()
            return jsonify({"error": "User not found"}), 404
        user_name = user[0]

        # Get event_name and category
        cur.execute("SELECT event_name, category FROM events WHERE event_id = %s", (event_id,))
        event = cur.fetchone()
        if not event:
            cur.close()
            return jsonify({"error": "Event not found"}), 404
        event_name, category = event

        # Insert into participants
        cur.execute("""
            INSERT INTO participants (user_id, user_name, event_id, event_name, category)
            VALUES (%s, %s, %s, %s, %s)
        """, (user_id, user_name, event_id, event_name, category))

        mysql.connection.commit()
        cur.close()

        return jsonify({"message": "Successfully registered for the event"}), 201

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/user/view-events-by-category', methods=['GET'])
@jwt_required()
def user_events_by_category():
    claims = get_jwt()
    if claims.get("role") != "user":
        return jsonify({"error": "user only"}), 403

    data = request.get_json()
    category = data.get("category")

    if not category:
        return jsonify({"error": "Category is required"}), 400

    try:
        cur = mysql.connection.cursor()
        cur.execute("""
            SELECT event_id, event_name, category, event_description, 
                   rules, event_date, event_time, venue, image_path
            FROM events
            WHERE category = %s
        """, (category,))
        rows = cur.fetchall()
        cur.close()

        events = []
        for row in rows:
            events.append({
                "event_id": row[0],
                "event_name": row[1],
                "category": row[2],
                "event_description": row[3],
                "rules": row[4],
                "event_date": str(row[5]),
                "event_time": str(row[6]).rsplit(':', 1)[0],  # Remove seconds if present
                "venue": row[7],
                "image_path": row[8]
            })

        if not events:
            return jsonify({"message": f"No events found under category '{category}'"}), 200

        return jsonify({"category": category, "events": events}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)