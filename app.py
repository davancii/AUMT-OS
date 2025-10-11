from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
import firebase_admin
from firebase_admin import credentials, auth, firestore
import os
from dotenv import load_dotenv
from datetime import datetime, timezone
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import time

# Load environment variables
load_dotenv()

app = Flask(__name__, static_folder='static')
app.secret_key = os.getenv('SECRET_KEY')

# Initialize Firebase
if not firebase_admin._apps:
    # Use environment variables for production security
    if os.getenv('FIREBASE_PROJECT_ID'):
        # Production: Use environment variables
        print("[+] Production: Using .env file")
        cred = credentials.Certificate({
            "type": "service_account",
            "project_id": os.getenv('FIREBASE_PROJECT_ID'),
            "private_key_id": os.getenv('FIREBASE_PRIVATE_KEY_ID'),
            "private_key": os.getenv('FIREBASE_PRIVATE_KEY').replace('\\n', '\n'),
            "client_email": os.getenv('FIREBASE_CLIENT_EMAIL'),
            "client_id": os.getenv('FIREBASE_CLIENT_ID'),
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
            "client_x509_cert_url": os.getenv('FIREBASE_CLIENT_X509_CERT_URL'),
            "universe_domain": "googleapis.com"
        })
    else:
        # Development: Use local file (for testing only)
        try:
            print("[+] Development: Using local file")
            cred = credentials.Certificate('firebase-service-account.json')
        except FileNotFoundError:
            print("Firebase service account file not found. Please set up environment variables for production.")
            raise
    
    firebase_admin.initialize_app(cred)

db = firestore.client()

# Email configuration
EMAIL_HOST = os.getenv('EMAIL_HOST', 'smtp.gmail.com')
EMAIL_PORT = int(os.getenv('EMAIL_PORT', '587'))
EMAIL_USER = os.getenv('EMAIL_USER', '')
EMAIL_PASSWORD = os.getenv('EMAIL_PASSWORD', '')

def verify_firebase_token_with_retry(id_token, max_retries=3):
    """
    Verify Firebase ID token with retry mechanism to handle clock skew issues
    """
    for attempt in range(max_retries):
        try:
            decoded_token = auth.verify_id_token(id_token, check_revoked=True)
            return decoded_token
        except Exception as e:
            if "Token used too early" in str(e) and attempt < max_retries - 1:
                print(f"Clock skew detected, retrying token verification (attempt {attempt + 1}/{max_retries})...")
                time.sleep(2 ** attempt)  # Exponential backoff: 1s, 2s, 4s
                continue
            else:
                raise e
    raise Exception("Failed to verify token after all retries")

@app.route('/')
def index():
    if 'user' in session:
        user_role = session['user'].get('role', 'member')
        if user_role == 'admin':
            return redirect(url_for('admin_dashboard'))
        else:
            return redirect(url_for('member_dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    # Firebase configuration for frontend
    firebase_config = {
        'apiKey': os.getenv('FIREBASE_API_KEY', ''),
        'authDomain': f"{os.getenv('FIREBASE_PROJECT_ID', '')}.firebaseapp.com",
        'projectId': os.getenv('FIREBASE_PROJECT_ID', ''),
        'storageBucket': f"{os.getenv('FIREBASE_PROJECT_ID', '')}.appspot.com",
        'messagingSenderId': os.getenv('FIREBASE_MESSAGING_SENDER_ID', ''),
        'appId': os.getenv('FIREBASE_APP_ID', '')
    }
    
    return render_template('login.html', firebase_config=firebase_config)

@app.route('/api/verify-token', methods=['POST'])
def verify_token():
    """Verify Firebase Auth ID token and set session"""
    try:
        data = request.get_json()
        id_token = data.get('idToken')
        
        if not id_token:
            return jsonify({'success': False, 'error': 'No token provided'})
        
        # Verify the ID token with Firebase Admin SDK using retry mechanism
        decoded_token = verify_firebase_token_with_retry(id_token)
        
        uid = decoded_token['uid']
        email = decoded_token.get('email')
        
        # Get user data from Firestore
        user_doc = db.collection('users').document(uid).get()
        if not user_doc.exists:
            # If user doesn't exist in Firestore, create a basic profile
            # This handles cases where user was created in Firebase Auth but not in Firestore
            user_data = {
                'name': decoded_token.get('name', ''),
                'email': email,
                'role': 'member',  # Default role
                'department': '',
                'phone': '',
                'points': 0,
                'created_at': datetime.now()
            }
            db.collection('users').document(uid).set(user_data)
        else:
            user_data = user_doc.to_dict()
        
        # Set session data
        session['user'] = {
            'uid': uid,
            'email': email,
            'name': user_data.get('name', ''),
            'role': user_data.get('role', 'member'),
            'department': user_data.get('department', ''),
            'phone': user_data.get('phone', ''),
            'points': user_data.get('points', 0)
        }
        
        return jsonify({
            'success': True, 
            'role': user_data.get('role', 'member'),
            'redirect_url': url_for('admin_dashboard') if user_data.get('role') == 'admin' else url_for('member_dashboard')
        })
        
    except Exception as e:
        print(f"Token verification error: {str(e)}")
        
        # Provide short, user-friendly error messages
        error_message = 'Authentication failed.'
        
        if "Token used too early" in str(e):
            error_message = 'Please try again.'
        elif "Token expired" in str(e):
            error_message = 'Session expired.'
        elif "Invalid token" in str(e):
            error_message = 'Invalid authentication.'
        elif "Token verification failed" in str(e):
            error_message = 'Authentication failed.'
        elif "User not found" in str(e):
            error_message = 'User not found.'
        
        return jsonify({'success': False, 'error': error_message})

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('login'))

@app.route('/api/logout', methods=['POST'])
def api_logout():
    """API endpoint for logout (used by frontend)"""
    session.pop('user', None)
    return jsonify({'success': True, 'message': 'Logged out successfully'})

@app.route('/admin')
def admin_dashboard():
    if 'user' not in session or session['user'].get('role') != 'admin':
        return redirect(url_for('login'))
    
    # Firebase configuration for frontend
    firebase_config = {
        'apiKey': os.getenv('FIREBASE_API_KEY', ''),
        'authDomain': f"{os.getenv('FIREBASE_PROJECT_ID', '')}.firebaseapp.com",
        'projectId': os.getenv('FIREBASE_PROJECT_ID', ''),
        'storageBucket': f"{os.getenv('FIREBASE_PROJECT_ID', '')}.appspot.com",
        'messagingSenderId': os.getenv('FIREBASE_MESSAGING_SENDER_ID', ''),
        'appId': os.getenv('FIREBASE_APP_ID', '')
    }
    
    # Get all members
    members = []
    members_ref = db.collection('users')
    for doc in members_ref.stream():
        member_data = doc.to_dict()
        member_data['id'] = doc.id
        members.append(member_data)
    
    # Sort members by points for ranking
    members_sorted = sorted(members, key=lambda x: x.get('points', 0), reverse=True)
    
    # Add rank to each member
    for i, member in enumerate(members_sorted):
        member['rank'] = i + 1
    
    # Calculate some statistics
    total_points = sum(member.get('points', 0) for member in members)
    avg_points = round(total_points / len(members)) if members else 0
    
    # Get today's attendance count
    today = datetime.now().strftime('%Y-%m-%d')
    today_attendance = 0
    attendance_ref = db.collection('attendance').where('date', '==', today)
    for doc in attendance_ref.stream():
        if doc.to_dict().get('status') == 'present':
            today_attendance += 1
    
    return render_template('admin_dashboard.html', 
                         members=members_sorted, 
                         total_points=total_points,
                         avg_points=avg_points,
                         today_attendance=today_attendance,
                         firebase_config=firebase_config)

@app.route('/member')
def member_dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    # Firebase configuration for frontend
    firebase_config = {
        'apiKey': os.getenv('FIREBASE_API_KEY', ''),
        'authDomain': f"{os.getenv('FIREBASE_PROJECT_ID', '')}.firebaseapp.com",
        'projectId': os.getenv('FIREBASE_PROJECT_ID', ''),
        'storageBucket': f"{os.getenv('FIREBASE_PROJECT_ID', '')}.appspot.com",
        'messagingSenderId': os.getenv('FIREBASE_MESSAGING_SENDER_ID', ''),
        'appId': os.getenv('FIREBASE_APP_ID', '')
    }
    
    user = session['user']
    
    # Get all members to calculate rank
    members = []
    members_ref = db.collection('users')
    for doc in members_ref.stream():
        member_data = doc.to_dict()
        member_data['id'] = doc.id
        members.append(member_data)
    
    # Sort members by points (descending) to calculate rank
    members_sorted = sorted(members, key=lambda x: x.get('points', 0), reverse=True)
    
    # Find current user's rank
    user_rank = 1
    for i, member in enumerate(members_sorted):
        if member['id'] == user['uid']:
            user_rank = i + 1
            break
    
    # Calculate attendance rate (simplified - you can enhance this)
    attendance_count = 0
    total_days = 30  # Last 30 days
    attendance_ref = db.collection('attendance').where('user_id', '==', user['uid']).limit(30)
    for doc in attendance_ref.stream():
        if doc.to_dict().get('status') == 'present':
            attendance_count += 1
    
    attendance_rate = round((attendance_count / total_days) * 100) if total_days > 0 else 0
    
    # Get recent points activity
    recent_points = []
    points_ref = db.collection('point_logs').where('user_id', '==', user['uid']).limit(5)
    for doc in points_ref.stream():
        points_data = doc.to_dict()
        points_data['id'] = doc.id
        recent_points.append(points_data)
    
    # Sort recent points by timestamp
    recent_points.sort(key=lambda x: x.get('timestamp', datetime.min), reverse=True)
    
    # Get recent attendance
    recent_attendance = []
    attendance_ref = db.collection('attendance').where('user_id', '==', user['uid']).limit(10)
    for doc in attendance_ref.stream():
        attendance_data = doc.to_dict()
        attendance_data['id'] = doc.id
        recent_attendance.append(attendance_data)
    
    # Sort recent attendance by timestamp
    recent_attendance.sort(key=lambda x: x.get('timestamp', datetime.min), reverse=True)
    
    return render_template('member_dashboard.html', 
                         user=user, 
                         user_rank=user_rank,
                         total_members=len(members),
                         attendance_rate=attendance_rate,
                         recent_points=recent_points,
                         recent_attendance=recent_attendance,
                         firebase_config=firebase_config)

@app.route('/admin/add_member', methods=['POST'])
def add_member():
    if 'user' not in session or session['user'].get('role') != 'admin':
        return redirect(url_for('login'))
    
    name = request.form['name']
    email = request.form['email']
    phone = request.form['phone']
    department = request.form['department']
    role = request.form['role']
    password = request.form['password']
    
    try:
        # Create user in Firebase Auth
        user = auth.create_user(
            email=email,
            password=password,
            display_name=name
        )
        
        # Add user data to Firestore using Firebase Auth UID
        user_data = {
            'name': name,
            'email': email,
            'phone': phone,
            'department': department,
            'role': role,
            'points': 0,
            'created_at': datetime.now()
        }
        
        # Store user data in Firestore using Firebase Auth UID
        db.collection('users').document(user.uid).set(user_data)
        flash('Member added successfully!')
        
    except auth.EmailAlreadyExistsError:
        flash('A user with this email already exists.')
    except Exception as e:
        flash(f'Error adding member: {str(e)}')
    
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/remove_member/<user_id>', methods=['POST'])
def remove_member(user_id):
    if 'user' not in session or session['user'].get('role') != 'admin':
        return redirect(url_for('login'))
    
    try:
        # Delete from Firestore
        db.collection('users').document(user_id).delete()
        
        # Delete from Firebase Auth
        auth.delete_user(user_id)
        
        flash('Member removed successfully!')
    except Exception as e:
        flash(f'Error removing member: {str(e)}')
    
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/update_points', methods=['POST'])
def update_points():
    if 'user' not in session or session['user'].get('role') != 'admin':
        return redirect(url_for('login'))
    
    user_id = request.form['user_id']
    points_change = int(request.form['points_change'])
    reason = request.form['reason']
    
    try:
        # Get current points
        user_doc = db.collection('users').document(user_id).get()
        if user_doc.exists:
            current_points = user_doc.to_dict().get('points', 0)
            new_points = current_points + points_change
            
            # Update points
            db.collection('users').document(user_id).update({
                'points': new_points
            })
            
            # Log the change
            db.collection('point_logs').add({
                'user_id': user_id,
                'points_change': points_change,
                'reason': reason,
                'timestamp': datetime.now(),
                'admin_id': session['user']['uid']
            })
            
            # Check for automatic warning
            user_data = user_doc.to_dict()
            user_name = user_data.get('name', 'Member')
            user_email = user_data.get('email', '')
            check_automatic_warning(user_id, new_points, user_name, user_email)
            
            flash('Points updated successfully!')
        else:
            flash('User not found!')
            
    except Exception as e:
        flash(f'Error updating points: {str(e)}')
    
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/bulk_update_points', methods=['POST'])
def bulk_update_points():
    if 'user' not in session or session['user'].get('role') != 'admin':
        return redirect(url_for('login'))
    
    points_change = int(request.form['points_change'])
    reason = request.form['reason']
    updated_count = 0
    
    try:
        # Get all form data
        for key, value in request.form.items():
            if key.startswith('member_points_') and value:  # Only process if member is selected
                user_id = key.replace('member_points_', '')
                
                # Get current points
                user_doc = db.collection('users').document(user_id).get()
                if user_doc.exists:
                    current_points = user_doc.to_dict().get('points', 0)
                    new_points = current_points + points_change
                    
                    # Update points
                    db.collection('users').document(user_id).update({
                        'points': new_points
                    })
                    
                    # Log the change
                    db.collection('point_logs').add({
                        'user_id': user_id,
                        'points_change': points_change,
                        'reason': reason,
                        'timestamp': datetime.now(),
                        'admin_id': session['user']['uid']
                    })
                    
                    # Check for automatic warning
                    user_data = user_doc.to_dict()
                    user_name = user_data.get('name', 'Member')
                    user_email = user_data.get('email', '')
                    check_automatic_warning(user_id, new_points, user_name, user_email)
                    
                    updated_count += 1
        
        if updated_count > 0:
            flash(f'Points updated successfully for {updated_count} member(s)!')
        else:
            flash('No members were selected for points update.')
            
    except Exception as e:
        flash(f'Error updating points: {str(e)}')
    
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/take_attendance', methods=['POST'])
def take_attendance():
    if 'user' not in session or session['user'].get('role') != 'admin':
        return redirect(url_for('login'))
    
    user_id = request.form['user_id']
    status = request.form['status']  # 'present' or 'absent'
    
    try:
        # Record attendance
        db.collection('attendance').add({
            'user_id': user_id,
            'status': status,
            'date': datetime.now().strftime('%Y-%m-%d'),
            'timestamp': datetime.now(),
            'taken_by': session['user']['uid']
        })
        
        flash('Attendance recorded successfully!')
    except Exception as e:
        flash(f'Error recording attendance: {str(e)}')
    
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/bulk_attendance', methods=['POST'])
def bulk_attendance():
    if 'user' not in session or session['user'].get('role') != 'admin':
        return redirect(url_for('login'))
    
    attendance_date = request.form.get('attendance_date', datetime.now().strftime('%Y-%m-%d'))
    recorded_count = 0
    
    try:
        # Get all form data
        for key, value in request.form.items():
            if key.startswith('status_') and value:  # Only process if status is not empty
                user_id = key.replace('status_', '')
                status = value
                
                # Check if attendance already exists for this user and date
                existing_attendance = db.collection('attendance').where('user_id', '==', user_id).where('date', '==', attendance_date).limit(1).stream()
                
                if not list(existing_attendance):  # No existing attendance found
                    # Record attendance
                    db.collection('attendance').add({
                        'user_id': user_id,
                        'status': status,
                        'date': attendance_date,
                        'timestamp': datetime.now(),
                        'taken_by': session['user']['uid']
                    })
                    recorded_count += 1
                else:
                    # Update existing attendance
                    existing_doc = db.collection('attendance').where('user_id', '==', user_id).where('date', '==', attendance_date).limit(1).stream()
                    for doc in existing_doc:
                        doc.reference.update({
                            'status': status,
                            'timestamp': datetime.now(),
                            'taken_by': session['user']['uid']
                        })
                        recorded_count += 1
        
        if recorded_count > 0:
            flash(f'Attendance recorded successfully for {recorded_count} member(s)!')
        else:
            flash('No attendance records were updated. Please select members and mark their status.')
            
    except Exception as e:
        flash(f'Error recording attendance: {str(e)}')
    
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/send_warning', methods=['POST'])
def send_warning():
    if 'user' not in session or session['user'].get('role') != 'admin':
        return redirect(url_for('login'))
    
    user_id = request.form['user_id']
    warning_message = request.form['warning_message']
    
    try:
        # Get user email
        user_doc = db.collection('users').document(user_id).get()
        if user_doc.exists:
            user_data = user_doc.to_dict()
            user_email = user_data['email']
            user_name = user_data['name']
            
            # Send email
            send_warning_email(user_email, user_name, warning_message)
            
            # Log the warning
            db.collection('warnings').add({
                'user_id': user_id,
                'message': warning_message,
                'sent_at': datetime.now(),
                'sent_by': session['user']['uid']
            })
            
            flash('Warning email sent successfully!')
        else:
            flash('User not found!')
            
    except Exception as e:
        flash(f'Error sending warning: {str(e)}')
    
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/bulk_send_warning', methods=['POST'])
def bulk_send_warning():
    if 'user' not in session or session['user'].get('role') != 'admin':
        return redirect(url_for('login'))
    
    warning_message = request.form['warning_message']
    sent_count = 0
    
    try:
        # Get all form data
        for key, value in request.form.items():
            if key.startswith('member_warning_') and value:  # Only process if member is selected
                user_id = key.replace('member_warning_', '')
                
                # Get user data
                user_doc = db.collection('users').document(user_id).get()
                if user_doc.exists:
                    user_data = user_doc.to_dict()
                    user_email = user_data['email']
                    user_name = user_data['name']
                    
                    # Send email with fixed subject
                    send_warning_email(user_email, user_name, warning_message)
                    
                    # Log the warning
                    db.collection('warnings').add({
                        'user_id': user_id,
                        'message': warning_message,
                        'sent_at': datetime.now(),
                        'sent_by': session['user']['uid']
                    })
                    
                    sent_count += 1
        
        if sent_count > 0:
            flash(f'Warning emails sent successfully to {sent_count} member(s)!')
        else:
            flash('No members were selected for warning emails.')
            
    except Exception as e:
        flash(f'Error sending warning emails: {str(e)}')
    
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/create_admin', methods=['GET', 'POST'])
def create_admin():
    if 'user' not in session or session['user'].get('role') != 'admin':
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        name = request.form['name']
        phone = request.form['phone']
        department = request.form['department']
        
        try:
            # Create user in Firebase Auth
            user = auth.create_user(
                email=email,
                password=password,
                display_name=name
            )
            
            # Add user data to Firestore using Firebase Auth UID
            user_data = {
                'name': name,
                'email': email,
                'phone': phone,
                'department': department,
                'role': 'admin',
                'points': 0,
                'created_at': datetime.now()
            }
            
            # Store user data in Firestore using Firebase Auth UID
            db.collection('users').document(user.uid).set(user_data)
            flash('Admin user created successfully!')
            return redirect(url_for('admin_dashboard'))
            
        except auth.EmailAlreadyExistsError:
            flash('A user with this email already exists.')
        except Exception as e:
            flash(f'Error creating admin user: {str(e)}')
    
    return render_template('create_admin.html')

@app.route('/admin/member/<user_id>')
def member_details(user_id):
    if 'user' not in session or session['user'].get('role') != 'admin':
        return redirect(url_for('login'))
    
    try:
        # Get member data
        user_doc = db.collection('users').document(user_id).get()
        if user_doc.exists:
            member_data = user_doc.to_dict()
            member_data['id'] = user_id
            
            # Get attendance history (without ordering to avoid index requirement)
            attendance_history = []
            attendance_ref = db.collection('attendance').where('user_id', '==', user_id).limit(30)
            for doc in attendance_ref.stream():
                attendance_data = doc.to_dict()
                attendance_data['id'] = doc.id
                attendance_history.append(attendance_data)
            
            # Sort attendance history in Python (most recent first)
            attendance_history.sort(key=lambda x: x.get('timestamp', datetime.min), reverse=True)
            
            # Get points history (without ordering to avoid index requirement)
            points_history = []
            points_ref = db.collection('point_logs').where('user_id', '==', user_id).limit(20)
            for doc in points_ref.stream():
                points_data = doc.to_dict()
                points_data['id'] = doc.id
                points_history.append(points_data)
            
            # Sort points history in Python (most recent first)
            points_history.sort(key=lambda x: x.get('timestamp', datetime.min), reverse=True)
            
            return render_template('member_details.html', 
                                 member=member_data, 
                                 attendance=attendance_history,
                                 points_history=points_history)
        else:
            flash('Member not found!')
            return redirect(url_for('admin_dashboard'))
            
    except Exception as e:
        flash(f'Error loading member details: {str(e)}')
        return redirect(url_for('admin_dashboard'))

def send_warning_email(to_email, user_name, message):
    """Send warning email to user"""
    try:
        # Check if email configuration is set up
        if not EMAIL_USER or not EMAIL_PASSWORD:
            print("Email configuration not set up. Please configure EMAIL_USER and EMAIL_PASSWORD in .env file")
            return False
            
        msg = MIMEMultipart()
        msg['From'] = EMAIL_USER
        msg['To'] = to_email
        msg['Subject'] = "AUMT OS - Warning Notice"
        
        body = f"""
        Dear {user_name},
        
        This is a warning notice from AUMT OS.
        
        Message: {message}
        
        Please take appropriate action.
        
        Best regards,
        AUMT OS Administration
        """
        
        msg.attach(MIMEText(body, 'plain'))
        
        server = smtplib.SMTP(EMAIL_HOST, EMAIL_PORT)
        server.starttls()
        server.login(EMAIL_USER, EMAIL_PASSWORD)
        text = msg.as_string()
        server.sendmail(EMAIL_USER, to_email, text)
        server.quit()
        
        print(f"Warning email sent successfully to {to_email}")
        return True
        
    except Exception as e:
        print(f"Error sending email to {to_email}: {str(e)}")
        return False

def check_automatic_warning(user_id, new_points, user_name, user_email):
    """
    Check if automatic warning should be sent when points drop to 50 or below
    
    This function:
    1. Checks if the user's points are 50 or below
    2. Prevents duplicate warnings within 24 hours
    3. Sends automatic warning email if conditions are met
    4. Logs the warning for tracking purposes
    
    Args:
        user_id (str): The user's unique ID
        new_points (int): The user's new point total
        user_name (str): The user's display name
        user_email (str): The user's email address
    
    Returns:
        bool: True if warning was sent, False otherwise
    """
    try:
        # Check if points are 50 or below
        if new_points <= 50:
            # Check if we've already sent a warning for this user recently (within last 24 hours)
            # Get all automatic warnings for this user and sort in Python to avoid index requirements
            warning_logs = db.collection('warning_logs').where('user_id', '==', user_id).where('type', '==', 'automatic').get()
            
            should_send_warning = True
            
            if warning_logs:
                # Sort by timestamp in Python to avoid Firestore index requirements
                sorted_warnings = sorted(warning_logs, key=lambda x: x.to_dict()['timestamp'], reverse=True)
                last_warning = sorted_warnings[0].to_dict()
                last_warning_time = last_warning['timestamp']
                
                # Handle timezone-aware vs timezone-naive datetime comparison
                current_time = datetime.now()
                if last_warning_time.tzinfo is not None:
                    # Firestore timestamp is timezone-aware, make current_time timezone-aware too
                    current_time = current_time.replace(tzinfo=timezone.utc)
                elif current_time.tzinfo is not None:
                    # Current time is timezone-aware, make Firestore timestamp timezone-naive
                    last_warning_time = last_warning_time.replace(tzinfo=None)
                
                # Check if last warning was within 24 hours
                time_diff = current_time - last_warning_time
                if time_diff.total_seconds() < 24 * 60 * 60:  # 24 hours in seconds
                    should_send_warning = False
            
            if should_send_warning:
                # Send automatic warning email
                warning_message = f"Your points have dropped to {new_points}. Please improve your performance to maintain good standing in the AUMT team."
                print(f"Attempting to send automatic warning to {user_name} ({user_email}) - Points: {new_points}")
                email_sent = send_warning_email(user_email, user_name, warning_message)
                
                if email_sent:
                    # Log the automatic warning
                    db.collection('warning_logs').add({
                        'user_id': user_id,
                        'type': 'automatic',
                        'message': warning_message,
                        'points': new_points,
                        'timestamp': datetime.now(timezone.utc),
                        'admin_id': 'system'
                    })
                    print(f"✅ Automatic warning sent successfully to {user_name} ({user_email}) - Points: {new_points}")
                    return True
                else:
                    print(f"❌ Failed to send automatic warning to {user_name} ({user_email}) - Check email configuration")
                    return False
        return False
    except Exception as e:
        print(f"Error checking automatic warning: {str(e)}")
        return False


if __name__ == '__main__':
    app.run(debug=True)
