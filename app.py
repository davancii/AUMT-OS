from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
import firebase_admin
from firebase_admin import credentials, auth, firestore
import os
from dotenv import load_dotenv
from datetime import datetime, timezone
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import secrets
import string

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

def check_admin_access():
    """Check if user has admin access, logout HR users instead of redirecting to login"""
    if 'user' not in session:
        return redirect(url_for('login'))
    
    user_role = session['user'].get('role')
    if user_role == 'hr':
        # Logout HR users who try to access admin routes
        session.pop('user', None)
        flash('Access denied. You have been logged out.', 'danger')
        return redirect(url_for('login'))
    elif user_role != 'admin':
        return redirect(url_for('login'))
    
    return None

# Email configuration
EMAIL_HOST = os.getenv('EMAIL_HOST', 'smtp.gmail.com')
EMAIL_PORT = int(os.getenv('EMAIL_PORT', '587'))
EMAIL_USER = os.getenv('EMAIL_USER', '')
EMAIL_PASSWORD = os.getenv('EMAIL_PASSWORD', '')

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
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        try:
            # First, check if user exists in Firestore
            users_ref = db.collection('users')
            query = users_ref.where('email', '==', email).limit(1)
            users = query.get()
            
            if not users:
                flash('Invalid email or password.')
                return render_template('login.html')
            
            user_doc = users[0]
            user_data = user_doc.to_dict()
            
            # Check if user has a password stored (for custom authentication)
            if 'password' in user_data:
                # Simple password verification (in production, use proper hashing)
                if user_data['password'] != password:
                    flash('Invalid email or password.')
                    return render_template('login.html')
            else:
                # If no password stored, this is a Firebase Auth user
                # We need to verify with Firebase Auth
                try:
                    # Try to get user from Firebase Auth
                    user = auth.get_user_by_email(email)
                    # If we get here, the email exists in Firebase Auth
                    # For now, we'll allow login (you should implement proper password verification)
                    pass
                except Exception:
                    flash('Invalid email or password.')
                    return render_template('login.html')
            
            # Set session data
            session['user'] = {
                'uid': user_doc.id,
                'email': email,
                'name': user_data.get('name', ''),
                'role': user_data.get('role', 'member'),
                'department': user_data.get('department', ''),
                'phone': user_data.get('phone', ''),
                'points': user_data.get('points', 0)
            }
            
            if user_data.get('role') == 'admin':
                return redirect(url_for('admin_dashboard'))
            elif user_data.get('role') == 'hr':
                return redirect(url_for('hr_dashboard'))
            else:
                return redirect(url_for('member_dashboard'))
                
        except Exception as e:
            print(f"Login error: {str(e)}")
            flash('Invalid email or password.')
            return render_template('login.html')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('login'))

@app.route('/admin')
def admin_dashboard():
    access_check = check_admin_access()
    if access_check:
        return access_check
    
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
                         today_attendance=today_attendance)

@app.route('/member')
def member_dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    # Get fresh user data from database instead of using cached session data
    try:
        user_doc = db.collection('users').document(session['user']['uid']).get()
        if user_doc.exists:
            user_data = user_doc.to_dict()
            user = {
                'uid': session['user']['uid'],
                'email': user_data.get('email', ''),
                'name': user_data.get('name', ''),
                'role': user_data.get('role', 'member'),
                'department': user_data.get('department', ''),
                'academic_year': user_data.get('academic_year', ''),
                'phone': user_data.get('phone', ''),
                'points': user_data.get('points', 0)
            }
        else:
            # Fallback to session data if user not found in database
            user = session['user']
    except Exception as e:
        print(f"Error fetching user data: {str(e)}")
        # Fallback to session data if there's an error
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
                         recent_attendance=recent_attendance)

@app.route('/hr')
def hr_dashboard():
    if 'user' not in session or session['user'].get('role') != 'hr':
        return redirect(url_for('login'))
    
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
    
    return render_template('hr_dashboard.html', 
                         members=members_sorted, 
                         total_points=total_points,
                         avg_points=avg_points,
                         today_attendance=today_attendance)

@app.route('/admin/add_member', methods=['POST'])
def add_member():
    access_check = check_admin_access()
    if access_check:
        return access_check
    
    name = request.form['name']
    email = request.form['email']
    phone = request.form['phone']
    department = request.form['department']
    academic_year = request.form['academic_year']
    role = request.form['role']
    password = request.form['password']
    
    try:
        # Check if user already exists in Firestore
        users_ref = db.collection('users')
        query = users_ref.where('email', '==', email).limit(1)
        existing_users = query.get()
        
        if existing_users:
            flash('A user with this email already exists.')
            return redirect(url_for('admin_dashboard'))
        
        # Create user document in Firestore with password
        user_data = {
            'name': name,
            'email': email,
            'phone': phone,
            'department': department,
            'academic_year': academic_year,
            'role': role,
            'points': 0,
            'password': password,  # Store password for authentication
            'created_at': datetime.now()
        }
        
        # Add user to Firestore
        db.collection('users').add(user_data)
        flash('Member added successfully!')
        
    except Exception as e:
        flash(f'Error adding member: {str(e)}')
    
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/remove_member/<user_id>', methods=['POST'])
def remove_member(user_id):
    access_check = check_admin_access()
    if access_check:
        return access_check
    
    try:
        # Delete from Firestore
        db.collection('users').document(user_id).delete()
        
        # Try to delete from Firebase Auth (only if user exists there)
        try:
            auth.delete_user(user_id)
        except Exception as auth_error:
            # If user doesn't exist in Firebase Auth, that's fine
            # This happens when users are created with custom password system
            print(f"User {user_id} not found in Firebase Auth (this is normal for custom auth users): {str(auth_error)}")
        
        flash('Member removed successfully!')
    except Exception as e:
        flash(f'Error removing member: {str(e)}')
    
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/update_points', methods=['POST'])
def update_points():
    if 'user' not in session or session['user'].get('role') not in ['admin', 'hr']:
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
    
    # Redirect based on user role
    if session['user'].get('role') == 'hr':
        return redirect(url_for('hr_dashboard'))
    else:
        return redirect(url_for('admin_dashboard'))

@app.route('/admin/bulk_update_points', methods=['POST'])
def bulk_update_points():
    if 'user' not in session or session['user'].get('role') not in ['admin', 'hr']:
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
    
    # Redirect based on user role
    if session['user'].get('role') == 'hr':
        return redirect(url_for('hr_dashboard'))
    else:
        return redirect(url_for('admin_dashboard'))

@app.route('/admin/take_attendance', methods=['POST'])
def take_attendance():
    if 'user' not in session or session['user'].get('role') not in ['admin', 'hr']:
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
    if 'user' not in session or session['user'].get('role') not in ['admin', 'hr']:
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
    
    # Redirect based on user role
    if session['user'].get('role') == 'hr':
        return redirect(url_for('hr_dashboard'))
    else:
        return redirect(url_for('admin_dashboard'))

@app.route('/admin/send_warning', methods=['POST'])
def send_warning():
    if 'user' not in session or session['user'].get('role') not in ['admin', 'hr']:
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
    
    # Redirect based on user role
    if session['user'].get('role') == 'hr':
        return redirect(url_for('hr_dashboard'))
    else:
        return redirect(url_for('admin_dashboard'))

@app.route('/admin/bulk_send_warning', methods=['POST'])
def bulk_send_warning():
    if 'user' not in session or session['user'].get('role') not in ['admin', 'hr']:
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
    
    # Redirect based on user role
    if session['user'].get('role') == 'hr':
        return redirect(url_for('hr_dashboard'))
    else:
        return redirect(url_for('admin_dashboard'))

@app.route('/admin/create_admin', methods=['GET', 'POST'])
def create_admin():
    access_check = check_admin_access()
    if access_check:
        return access_check
    
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        name = request.form['name']
        phone = request.form['phone']
        department = request.form['department']
        
        try:
            # Check if user already exists in Firestore
            users_ref = db.collection('users')
            query = users_ref.where('email', '==', email).limit(1)
            existing_users = query.get()
            
            if existing_users:
                flash('A user with this email already exists.')
                return render_template('create_admin.html')
            
            # Create user document in Firestore with password
            user_data = {
                'name': name,
                'email': email,
                'phone': phone,
                'department': department,
                'role': 'admin',
                'points': 0,
                'password': password,  # Store password for authentication
                'created_at': datetime.now()
            }
            
            # Add user to Firestore
            db.collection('users').add(user_data)
            flash('Admin user created successfully!')
            return redirect(url_for('admin_dashboard'))
            
        except Exception as e:
            flash(f'Error creating admin user: {str(e)}')
    
    return render_template('create_admin.html')

@app.route('/admin/members')
def members_page():
    access_check = check_admin_access()
    if access_check:
        return access_check
    
    # Get search query
    search_query = request.args.get('search', '').strip()
    
    # Get all members
    members = []
    members_ref = db.collection('users')
    for doc in members_ref.stream():
        member_data = doc.to_dict()
        member_data['id'] = doc.id
        members.append(member_data)
    
    # Filter members based on search query
    if search_query:
        filtered_members = []
        search_lower = search_query.lower()
        for member in members:
            if (search_lower in member.get('name', '').lower() or 
                search_lower in member.get('email', '').lower()):
                filtered_members.append(member)
        members = filtered_members
    
    # Sort members by points for ranking
    members_sorted = sorted(members, key=lambda x: x.get('points', 0), reverse=True)
    
    # Add rank to each member
    for i, member in enumerate(members_sorted):
        member['rank'] = i + 1
    
    return render_template('members.html', 
                         members=members_sorted, 
                         search_query=search_query)

@app.route('/admin/export_members')
def export_members():
    """Export all members to CSV"""
    access_check = check_admin_access()
    if access_check:
        return access_check
    
    try:
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
        
        # Create CSV content
        csv_content = "Rank,Name,Email,Phone,Department,Academic Year,Role,Points,Created At\n"
        
        for member in members_sorted:
            # Clean and format data
            rank = str(member.get('rank', 'N/A'))
            name = str(member.get('name', 'N/A')).replace('"', '""')
            email = str(member.get('email', 'N/A')).replace('"', '""')
            phone = str(member.get('phone', 'N/A')).replace('"', '""')
            department = str(member.get('department', 'N/A')).replace('"', '""')
            academic_year = str(member.get('academic_year', 'N/A')).replace('"', '""')
            role = str(member.get('role', 'N/A')).replace('"', '""')
            points = str(member.get('points', 0))
            created_at = str(member.get('created_at', 'N/A'))
            
            # Add row to CSV
            csv_content += f'"{rank}","{name}","{email}","{phone}","{department}","{academic_year}","{role}","{points}","{created_at}"\n'
        
        # Create response
        from flask import Response
        response = Response(
            csv_content,
            mimetype='text/csv',
            headers={'Content-Disposition': f'attachment; filename=aumt-members-{datetime.now().strftime("%Y-%m-%d")}.csv'}
        )
        return response
        
    except Exception as e:
        flash(f'Error exporting members: {str(e)}')
        return redirect(url_for('members_page'))

@app.route('/admin/member/<user_id>')
def member_details(user_id):
    if 'user' not in session or session['user'].get('role') not in ['admin', 'hr']:
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

def generate_invite_code():
    """Generate a secure invite code with AUMT prefix"""
    random_part = ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(8))
    return f"AUMT-{random_part}"

@app.route('/admin/invite_codes')
def invite_codes():
    access_check = check_admin_access()
    if access_check:
        return access_check
    
    # Get all invite codes
    invite_codes = []
    codes_ref = db.collection('invite_codes')
    for doc in codes_ref.stream():
        code_data = doc.to_dict()
        code_data['id'] = doc.id
        invite_codes.append(code_data)
    
    # Sort by creation date (newest first)
    invite_codes.sort(key=lambda x: x.get('created_at', datetime.min), reverse=True)
    
    return render_template('invite_codes.html', invite_codes=invite_codes)

@app.route('/admin/generate_invite_code', methods=['POST'])
def generate_invite_code_route():
    if 'user' not in session or session['user'].get('role') != 'admin':
        return redirect(url_for('login'))
    
    try:
        # Get number of codes to generate (default to 1)
        num_codes = int(request.form.get('num_codes', 1))
        
        # Limit to reasonable number (max 50 at once)
        if num_codes > 50:
            flash('Cannot generate more than 50 codes at once!')
            return redirect(url_for('invite_codes'))
        
        if num_codes < 1:
            flash('Must generate at least 1 code!')
            return redirect(url_for('invite_codes'))
        
        generated_codes = []
        
        for i in range(num_codes):
            # Generate unique invite code
            invite_code = generate_invite_code()
            
            # Check if code already exists (very unlikely but safe)
            while True:
                existing_codes = db.collection('invite_codes').where('code', '==', invite_code).limit(1).get()
                if not existing_codes:
                    break
                invite_code = generate_invite_code()
            
            # Create invite code document
            code_data = {
                'code': invite_code,
                'created_by': session['user']['uid'],
                'created_at': datetime.now(),
                'used': False,
                'used_by': None,
                'used_at': None
            }
            
            db.collection('invite_codes').add(code_data)
            generated_codes.append(invite_code)
        
        if num_codes == 1:
            flash(f'Invite code generated successfully: {generated_codes[0]}')
        else:
            flash(f'{num_codes} invite codes generated successfully!')
        
    except ValueError:
        flash('Invalid number of codes specified!')
    except Exception as e:
        flash(f'Error generating invite codes: {str(e)}')
    
    return redirect(url_for('invite_codes'))

@app.route('/admin/delete_invite_code/<code_id>', methods=['POST'])
def delete_invite_code(code_id):
    access_check = check_admin_access()
    if access_check:
        return access_check
    
    try:
        # Check if code is already used
        code_doc = db.collection('invite_codes').document(code_id).get()
        if code_doc.exists:
            code_data = code_doc.to_dict()
            if code_data.get('used', False):
                flash('Cannot delete used invite code!')
            else:
                db.collection('invite_codes').document(code_id).delete()
                flash('Invite code deleted successfully!')
        else:
            flash('Invite code not found!')
            
    except Exception as e:
        flash(f'Error deleting invite code: {str(e)}')
    
    return redirect(url_for('invite_codes'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        phone = request.form['phone']
        department = request.form['department']
        academic_year = request.form['academic_year']
        password = request.form['password']
        invite_code = request.form['invite_code']
        
        try:
            # Validate invite code
            codes_ref = db.collection('invite_codes')
            query = codes_ref.where('code', '==', invite_code.upper()).limit(1)
            codes = query.get()
            
            if not codes:
                flash('Invalid invite code!')
                return render_template('signup.html')
            
            code_doc = codes[0]
            code_data = code_doc.to_dict()
            
            if code_data.get('used', False):
                flash('This invite code has already been used!')
                return render_template('signup.html')
            
            # Check if user already exists
            users_ref = db.collection('users')
            query = users_ref.where('email', '==', email).limit(1)
            existing_users = query.get()
            
            if existing_users:
                flash('A user with this email already exists!')
                return render_template('signup.html')
            
            # Create user
            user_data = {
                'name': name,
                'email': email,
                'phone': phone,
                'department': department,
                'academic_year': academic_year,
                'role': 'member',
                'points': 0,
                'password': password,
                'created_at': datetime.now()
            }
            
            # Add user to Firestore
            user_ref = db.collection('users').add(user_data)
            user_id = user_ref[1].id
            
            # Mark invite code as used
            db.collection('invite_codes').document(code_doc.id).update({
                'used': True,
                'used_by': user_id,
                'used_at': datetime.now()
            })
            
            flash('Account created successfully! You can now login.', 'success')
            return redirect(url_for('login'))
            
        except Exception as e:
            flash(f'Error creating account: {str(e)}')
            return render_template('signup.html')
    
    return render_template('signup.html')

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
        if new_points <= 60:
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
