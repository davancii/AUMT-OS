# AUMT OS - Advanced User Management & Tracking System

A comprehensive web application built with Flask and Firebase for managing members, tracking attendance, and managing points.

## Features

### Admin Features
- **Member Management**: Add, remove, and view all members
- **Attendance Tracking**: Take attendance for members
- **Points System**: Add or remove points from members
- **Warning System**: Send warning emails to members
- **Member Details**: View detailed information about each member
- **Dashboard**: Overview of all system statistics

### Member Features
- **Personal Dashboard**: View personal information and statistics
- **Points Tracking**: See current points and history
- **Attendance History**: View personal attendance records

## Technology Stack

- **Backend**: Python Flask
- **Database**: Firebase Firestore
- **Authentication**: Firebase Authentication
- **Frontend**: HTML, CSS, Bootstrap 5, Font Awesome
- **Email**: SMTP for sending warnings

## Setup Instructions

### 1. Prerequisites
- Python 3.7 or higher
- Firebase project with Authentication and Firestore enabled
- Gmail account for sending emails (optional)

### 2. Installation

1. Clone or download this project
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Set up Firebase:
   - Go to [Firebase Console](https://console.firebase.google.com/)
   - Create a new project or use existing one
   - Enable Authentication (Email/Password)
   - Enable Firestore Database
   - Go to Project Settings > Service Accounts
   - Generate a new private key
   - Download the JSON file and rename it to `firebase-service-account.json`
   - Place it in the project root directory

4. Configure environment variables:
   - Copy `env_example.txt` to `.env`
   - Update the values with your configuration:
     ```env
     SECRET_KEY=your-secret-key-here
     EMAIL_HOST=smtp.gmail.com
     EMAIL_PORT=587
     EMAIL_USER=your-email@gmail.com
     EMAIL_PASSWORD=your-app-password
     ```

5. Run the application:
   ```bash
   python app.py
   ```

6. Open your browser and go to `http://localhost:5000`

### 3. Initial Setup

1. **Create Admin User**:
   - Go to Firebase Console > Authentication
   - Add a user manually with email and password
   - Go to Firestore Database
   - Create a document in the `users` collection with the user's UID
   - Set the document data:
     ```json
     {
       "name": "Admin Name",
       "email": "admin@example.com",
       "phone": "1234567890",
       "department": "Administration",
       "role": "admin",
       "points": 0,
       "created_at": "2024-01-01T00:00:00Z"
     }
     ```

2. **Login**: Use the admin credentials to login and start managing the system

## Usage

### Admin Dashboard
- **Add Members**: Click "Add Member" to create new user accounts
- **Take Attendance**: Record daily attendance for members
- **Manage Points**: Add or subtract points with reasons
- **Send Warnings**: Send email warnings to members
- **View Details**: Click the eye icon to see detailed member information

### Member Dashboard
- Members can view their personal information
- Check their current points and attendance history
- View their profile and statistics

## Database Structure

### Users Collection
```json
{
  "name": "string",
  "email": "string",
  "phone": "string",
  "department": "string",
  "role": "admin|member",
  "points": "number",
  "created_at": "timestamp"
}
```

### Attendance Collection
```json
{
  "user_id": "string",
  "status": "present|absent",
  "date": "string",
  "timestamp": "timestamp",
  "taken_by": "string"
}
```

### Point Logs Collection
```json
{
  "user_id": "string",
  "points_change": "number",
  "reason": "string",
  "timestamp": "timestamp",
  "admin_id": "string"
}
```

### Warnings Collection
```json
{
  "user_id": "string",
  "message": "string",
  "sent_at": "timestamp",
  "sent_by": "string"
}
```

## Security Notes

- Change the default SECRET_KEY in production
- Use environment variables for sensitive data
- Enable Firebase security rules for Firestore
- Use HTTPS in production
- Regularly backup your Firestore data

## Troubleshooting

1. **Firebase Connection Issues**: Ensure the service account JSON file is correctly placed and named
2. **Email Not Sending**: Check email credentials and enable "Less secure app access" or use App Passwords
3. **Authentication Errors**: Verify Firebase Authentication is enabled and properly configured

## License

This project is open source and available under the MIT License.
