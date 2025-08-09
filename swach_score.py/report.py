#code
import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import random
import json
import os
from pathlib import Path
import base64
from io import BytesIO
from PIL import Image
import zipfile
import time

# Page configuration
st.set_page_config(
    page_title="🚆 Swachh Score - Railway Cleanliness Dashboard",
    page_icon="🚆",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for animations and styling
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;600;700&display=swap');
    
    .main-header {
        background: linear-gradient(135deg, #FF6B35 0%, #F7931E 50%, #FFD700 100%);
        padding: 2rem;
        border-radius: 20px;
        margin-bottom: 2rem;
        text-align: center;
        box-shadow: 0 10px 30px rgba(155, 207, 53, 0.3);
        animation: fadeInDown 1s ease-out;
    }
    
    .main-header h1 {
        color: white;
        font-family: 'Poppins', sans-serif;
        font-weight: 700;
        font-size: 3rem;
        margin: 0;
        text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
    }
    
    .main-header p {
        color: white;
        font-family: 'Poppins', sans-serif;
        font-size: 1.3rem;
        margin: 0.5rem 0 0 0;
        opacity: 0.95;
    }
    
    /* Sustainability Banner */
    .sustainability-banner {
        background: linear-gradient(135deg, #4CAF50 0%, #2E7D32 100%);
        padding: 1.5rem;
        border-radius: 15px;
        margin: 1rem 0;
        color: white;
        text-align: center;
        animation: slideInLeft 1s ease-out;
        border-left: 5px solid #81C784;
    }
    
    .quote-carousel {
        background: linear-gradient(135deg, #F7981E 0%, #C8E6C9 100%);
        padding: 1.5rem;
        border-radius: 15px;
        margin: 1rem 0;
        text-align: center;
        border: 2px solid #4CAF50;
        animation: fadeIn 2s ease-out;
    }
    
    .environment-tip {
        background: linear-gradient(135deg, #81C784 0%, #66BB6A 100%);
        padding: 1rem;
        border-radius: 10px;
        margin: 0.5rem 0;
        color: white;
        font-weight: 500;
    }
    
    /* Admin Response Style */
    .admin-response {
        background: linear-gradient(135deg, #2196F3 0%, #1976D2 100%);
        padding: 1rem;
        border-radius: 10px;
        margin: 0.5rem 0;
        color: white;
        border-left: 4px solid #FFD700;
    }
    
    .response-notification {
        background: linear-gradient(135deg, #FF9800 0%, #F57C00 100%);
        padding: 1rem;
        border-radius: 10px;
        margin: 0.5rem 0;
        color: white;
        animation: pulse 2s infinite;
    }
    
    @keyframes pulse {
        0% { transform: scale(1); }
        50% { transform: scale(1.02); }
        100% { transform: scale(1); }
    }
    
    @keyframes fadeInDown {
        from {
            opacity: 0;
            transform: translateY(-30px);
        }
        to {
            opacity: 1;
            transform: translateY(0);
        }
    }
    
    @keyframes slideInLeft {
        from {
            opacity: 0;
            transform: translateX(-50px);
        }
        to {
            opacity: 1;
            transform: translateX(0);
        }
    }
    
    @keyframes fadeIn {
        from { opacity: 0; }
        to { opacity: 1; }
    }
    
    @keyframes bounceIn {
        0% {
            opacity: 0;
            transform: scale(0.3);
        }
        50% {
            opacity: 1;
            transform: scale(1.05);
        }
        70% {
            transform: scale(0.9);
        }
        100% {
            opacity: 1;
            transform: scale(1);
        }
    }
    
    .metric-card {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 1.5rem;
        border-radius: 15px;
        color: white;
        text-align: center;
        margin: 0.5rem;
        box-shadow: 0 8px 25px rgba(0,0,0,0.1);
        transition: transform 0.3s ease, box-shadow 0.3s ease;
        animation: bounceIn 0.8s ease-out;
    }
    
    .metric-card:hover {
        transform: translateY(-5px);
        box-shadow: 0 15px 35px rgba(0,0,0,0.2);
    }
    
    .metric-value {
        font-size: 2.5rem;
        font-weight: 700;
        font-family: 'Poppins', sans-serif;
    }
    
    .metric-label {
        font-size: 1rem;
        opacity: 0.9;
        font-family: 'Poppins', sans-serif;
    }
    
    .success-animation {
        animation: bounceIn 0.6s ease-out;
        background: linear-gradient(135deg, #4CAF50, #45a049);
        color: white;
        padding: 1rem;
        border-radius: 10px;
        text-align: center;
        margin: 1rem 0;
    }
    
    .report-card {
        background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
        padding: 1.5rem;
        border-radius: 15px;
        margin: 1rem 0;
        color: white;
        animation: slideInLeft 0.5s ease-out;
        transition: transform 0.3s ease;
    }
    
    .report-card:hover {
        transform: scale(1.02);
    }
    
    .admin-panel {
        background: linear-gradient(135deg, #2196F3 0%, #1976D2 100%);
        padding: 2rem;
        border-radius: 20px;
        margin: 1rem 0;
        color: white;
        animation: fadeInDown 0.8s ease-out;
    }
    
    .user-profile-card {
        background: linear-gradient(135deg, #FF9800 0%, #FF5722 100%);
        padding: 1.5rem;
        border-radius: 15px;
        color: white;
        text-align: center;
        animation: bounceIn 0.8s ease-out;
    }
    
    .stButton > button {
        background: linear-gradient(135deg, #FF6B35, #F7931E);
        color: white;
        border: none;
        border-radius: 25px;
        padding: 0.75rem 2rem;
        font-weight: 600;
        transition: all 0.3s ease;
        box-shadow: 0 4px 15px rgba(255, 107, 53, 0.3);
    }
    
    .stButton > button:hover {
        transform: translateY(-2px);
        box-shadow: 0 8px 25px rgba(255, 107, 53, 0.4);
    }
    
    .upload-area {
        border: 2px dashed #FF6B35;
        border-radius: 15px;
        padding: 2rem;
        text-align: center;
        background: linear-gradient(135deg, rgba(255, 107, 53, 0.1), rgba(247, 147, 30, 0.1));
        margin: 1rem 0;
        transition: all 0.3s ease;
    }
    
    .upload-area:hover {
        border-color: #F7931E;
        background: linear-gradient(135deg, rgba(255, 107, 53, 0.2), rgba(247, 147, 30, 0.2));
    }
    
    .login-success {
        background: linear-gradient(135deg, #4CAF50 0%, #45a049 100%);
        padding: 1rem;
        border-radius: 10px;
        color: white;
        text-align: center;
        margin: 1rem 0;
        animation: bounceIn 0.5s ease-out;
    }
</style>
""", unsafe_allow_html=True)

# Initialize session state with persistent data
def initialize_session_state():
    """Initialize session state with complete sample data"""
    # Initialize data only if not already present
    if 'initialized' not in st.session_state:
        st.session_state.initialized = True
        
        # Users database with default accounts
        st.session_state.users_db = {
            "admin": {
                "name": "System Administrator",
                "email": "admin@swachhscore.com",
                "phone": "1234567890",
                "password": "admin123",
                "user_type": "admin",
                "role_title": "Admin",
                "city": "New Delhi",
                "join_date": "2024-01-01",
                "total_points": None,
                "level": None,
                "reports_count": 0,
                "achievements": ["System Admin"],
                "favorite_routes": [],
                "is_admin": True,
                "employee_id": "ADM001",
                "department": "IT Administration"
            },
            "railway_officer": {
                "name": "Railway Officer",
                "email": "officer@indianrailways.gov.in",
                "phone": "9876543213",
                "password": "officer123",
                "user_type": "stakeholder",
                "role_title": "Railway Officer",
                "city": "New Delhi",
                "join_date": "2024-01-10",
                "total_points": None,
                "level": None,
                "reports_count": 0,
                "achievements": ["Quality Controller"],
                "favorite_routes": [],
                "is_stakeholder": True,
                "employee_id": "RLY001",
                "department": "Operations",
                "station_assigned": "New Delhi Zone"
            },
            "demo_user": {
                "name": "Demo Passenger",
                "email": "demo@example.com",
                "phone": "9999999999",
                "password": "demo123",
                "user_type": "passenger",
                "role_title": "Passenger",
                "city": "Mumbai",
                "join_date": "2024-02-01",
                "total_points": 150,
                "level": 4,
                "reports_count": 8,
                "achievements": ["First Reporter", "Eco Warrior", "Photo Detective"],
                "favorite_routes": ["Mumbai-Delhi", "Delhi-Kolkata"]
            }
        }
    
    # Initialize other components if not present
    if 'reports_db' not in st.session_state:
        st.session_state.reports_db = [
            {
                "id": "RPT_0001",
                "timestamp": datetime.now() - timedelta(days=2),
                "type": "Station",
                "location": "New Delhi",
                "category": "Toilets",
                "severity": "High",
                "description": "Toilet facilities are not properly maintained. Strong odor and lack of cleaning supplies.",
                "user": "demo_user",
                "status": "In Progress",
                "resolution_date": None,
                "image": "uploaded",
                "responses": [
                    {
                        "timestamp": datetime.now() - timedelta(days=1),
                        "responder": "railway_officer",
                        "responder_name": "Railway Officer",
                        "response_text": "Thank you for reporting. Our cleaning team has been notified and will address this issue within 24 hours.",
                        "status_update": "In Progress"
                    }
                ]
            },
            {
                "id": "RPT_0002",
                "timestamp": datetime.now() - timedelta(days=1),
                "type": "Train",
                "location": "Rajdhani Express (12001)",
                "category": "Platform/Coach Cleanliness",
                "severity": "Medium",
                "description": "Coach floors need better cleaning. Food packets and water bottles scattered.",
                "user": "demo_user",
                "status": "Open",
                "resolution_date": None,
                "image": None,
                "responses": []
            }
        ]
    
    if 'stations_db' not in st.session_state:
        st.session_state.stations_db = [
            {"date": datetime.now() - timedelta(days=5), "station": "New Delhi", "cleanliness_score": 7.8, "reports_count": 12},
            {"date": datetime.now() - timedelta(days=4), "station": "Mumbai Central", "cleanliness_score": 8.2, "reports_count": 8},
            {"date": datetime.now() - timedelta(days=3), "station": "Chennai Central", "cleanliness_score": 7.5, "reports_count": 15},
            {"date": datetime.now() - timedelta(days=2), "station": "Kolkata", "cleanliness_score": 6.9, "reports_count": 18},
            {"date": datetime.now() - timedelta(days=1), "station": "Bangalore City", "cleanliness_score": 8.5, "reports_count": 6},
        ]
    
    if 'trains_db' not in st.session_state:
        st.session_state.trains_db = [
            {"train_name": "Rajdhani Express", "train_number": "12001", "route": "New Delhi - Mumbai", 
             "cleanliness_score": 8.4, "total_reports": 25},
            {"train_name": "Shatabdi Express", "train_number": "12002", "route": "New Delhi - Chandigarh",
             "cleanliness_score": 9.1, "total_reports": 12},
            {"train_name": "Duronto Express", "train_number": "12005", "route": "Mumbai - Delhi",
             "cleanliness_score": 7.8, "total_reports": 18},
            {"train_name": "Vande Bharat", "train_number": "22626", "route": "Delhi - Varanasi",
             "cleanliness_score": 9.3, "total_reports": 8},
        ]
    
    if 'notifications_db' not in st.session_state:
        st.session_state.notifications_db = [
            {
                "id": "NOT_0001",
                "timestamp": datetime.now() - timedelta(hours=2),
                "recipient": "demo_user",
                "title": "Response to your report RPT_0001",
                "message": "Thank you for reporting. Our cleaning team has been notified and will address this issue within 24 hours.",
                "report_id": "RPT_0001",
                "responder_name": "Railway Officer",
                "read": False,
                "type": "response"
            }
        ]
    
    # Initialize current user state if not present
    if 'current_user' not in st.session_state:
        st.session_state.current_user = None
    
    # Add a flag to track if user is authenticated
    if 'authenticated' not in st.session_state:
        st.session_state.authenticated = False

# Sustainability quotes and tips


ENVIRONMENT_TIPS = [
    "🌱 Tip: Use reusable water bottles while traveling to reduce plastic waste",
    "♻️ Tip: Dispose of waste in designated bins to keep stations clean",
    "🌍 Tip: Report environmental issues to help maintain ecological balance",
    "🚆 Tip: Choose trains over flights to reduce carbon footprint",
    "🌿 Tip: Avoid littering - every piece of trash affects our environment",
    "💧 Tip: Conserve water in railway facilities - every drop counts"
]

# Initialize session state first thing
initialize_session_state()

def validate_user_login(username, password, expected_user_type):
    """Validate user credentials and type"""
    if not username or not password:
        return False, "Please enter both username and password"
    
    # Check if user exists
    if username not in st.session_state.users_db:
        return False, "User not found"
    
    user_data = st.session_state.users_db[username]
    
    # Check password
    if password != user_data.get('password', ''):
        return False, "Invalid password"
    
    # Check user type authorization
    user_role = user_data.get('user_type', 'passenger')
    if expected_user_type == "Admin/Stakeholder" and user_role not in ['admin', 'stakeholder']:
        return False, "Invalid user type for this account"
    elif expected_user_type == "Passenger" and user_role != 'passenger':
        return False, "This account is not registered as a passenger"
    
    return True, "Login successful"

def display_sustainability_banner():
    """Display rotating sustainability quotes and tips"""
    
    tip_index = int(time.time() / 15) % len(ENVIRONMENT_TIPS)
    
    col2 = st.columns([ 14])
    
  
    with col2:
        st.markdown(f"""
        <div class="environment-tip">
            <strong>{ENVIRONMENT_TIPS[tip_index]}</strong>
        </div>
        """, unsafe_allow_html=True)

def add_report(report):
    """Add a new report to the database"""
    try:
        report["id"] = f"RPT_{len(st.session_state.reports_db)+1:04d}"
        report["responses"] = []
        st.session_state.reports_db.append(report)
        
        # Update user points
        if report["user"] in st.session_state.users_db:
            points_earned = 10
            if report.get("image"):
                points_earned += 5
                
            current_points = st.session_state.users_db[report["user"]].get("total_points", 0)
            st.session_state.users_db[report["user"]]["total_points"] = current_points + points_earned
            st.session_state.users_db[report["user"]]["reports_count"] += 1
            st.session_state.users_db[report["user"]]["level"] = st.session_state.users_db[report["user"]]["total_points"] // 50 + 1
            
            # Add achievements
            achievements = st.session_state.users_db[report["user"]].get("achievements", [])
            if "First Reporter" not in achievements and st.session_state.users_db[report["user"]]["reports_count"] == 1:
                achievements.append("First Reporter")
            if "Eco Warrior" not in achievements and st.session_state.users_db[report["user"]]["reports_count"] >= 5:
                achievements.append("Eco Warrior")
            if "Photo Detective" not in achievements and report.get("image") and "Photo Detective" not in achievements:
                achievements.append("Photo Detective")
            st.session_state.users_db[report["user"]]["achievements"] = achievements
        
        return True
    except Exception as e:
        st.error(f"Error adding report: {e}")
        return False

def add_response_to_report(report_id, responder, response_text, status_update=None):
    """Add stakeholder/admin response to a report"""
    try:
        for i, report in enumerate(st.session_state.reports_db):
            if report.get('id') == report_id:
                if 'responses' not in report:
                    st.session_state.reports_db[i]['responses'] = []
                
                response = {
                    "timestamp": datetime.now(),
                    "responder": responder,
                    "responder_name": st.session_state.users_db.get(responder, {}).get('name', responder),
                    "response_text": response_text,
                    "status_update": status_update
                }
                
                st.session_state.reports_db[i]['responses'].append(response)
                
                if status_update:
                    st.session_state.reports_db[i]['status'] = status_update
                    if status_update == "Resolved":
                        st.session_state.reports_db[i]['resolution_date'] = datetime.now()
                
                # Create notification for the reporter
                reporter_username = report.get('user')
                if reporter_username:
                    notification = {
                        "id": f"NOT_{len(st.session_state.notifications_db)+1:04d}",
                        "timestamp": datetime.now(),
                        "recipient": reporter_username,
                        "title": f"Response to your report {report_id}",
                        "message": response_text,
                        "report_id": report_id,
                        "responder_name": st.session_state.users_db.get(responder, {}).get('name', responder),
                        "read": False,
                        "type": "response"
                    }
                    st.session_state.notifications_db.append(notification)
                
                return True
        return False
    except Exception as e:
        st.error(f"Error adding response: {e}")
        return False

def get_user_notifications(username):
    """Get notifications for a specific user"""
    return [n for n in st.session_state.notifications_db if n.get('recipient') == username]

def mark_notification_as_read(notification_id):
    """Mark a notification as read"""
    for i, notification in enumerate(st.session_state.notifications_db):
        if notification.get('id') == notification_id:
            st.session_state.notifications_db[i]['read'] = True
            break

def export_data():
    """Export all data as JSON"""
    data = {
        "users": st.session_state.users_db,
        "reports": st.session_state.reports_db,
        "stations": st.session_state.stations_db,
        "trains": st.session_state.trains_db,
        "notifications": st.session_state.notifications_db,
        "exported_at": datetime.now().isoformat()
    }
    return json.dumps(data, indent=2, default=str)

def perform_login(username, password, user_type):
    """Perform login and set session state"""
    is_valid, message = validate_user_login(username, password, user_type)
    
    if is_valid:
        st.session_state.current_user = username
        st.session_state.authenticated = True
        return True, message
    else:
        st.session_state.current_user = None
        st.session_state.authenticated = False
        return False, message

def perform_logout():
    """Perform logout and clear session state"""
    st.session_state.current_user = None
    st.session_state.authenticated = False

# Main title with enhanced styling

st.markdown("""
<div class="main-header">
    <h1>🚆 Swachh Score Dashboard</h1>
    <p>Real-Time Cleanliness Reporting & Analytics for Sustainable Indian Railways</p>
</div>
""", unsafe_allow_html=True)



# Convert data to DataFrames for easier manipulation
try:
    df_stations = pd.DataFrame(st.session_state.stations_db)
    if not df_stations.empty and 'date' in df_stations.columns:
        df_stations['date'] = pd.to_datetime(df_stations['date'])
    
    df_trains = pd.DataFrame(st.session_state.trains_db)
    df_reports = pd.DataFrame(st.session_state.reports_db)
    if not df_reports.empty and 'timestamp' in df_reports.columns:
        df_reports['timestamp'] = pd.to_datetime(df_reports['timestamp'])
except Exception as e:
    st.error(f"Data loading error: {e}")
    df_stations = pd.DataFrame()
    df_trains = pd.DataFrame()
    df_reports = pd.DataFrame()

# Enhanced User Login/Profile Section in Sidebar
st.sidebar.markdown("""
<div class="user-profile-card">
    <h3>👤 User Profile</h3>
</div>
""", unsafe_allow_html=True)

# Enhanced User authentication with better error handling
if not st.session_state.authenticated or st.session_state.current_user is None:
    with st.sidebar:
        auth_tab = st.radio("Choose an option:", ["Login", "Register"])
        
        if auth_tab == "Login":
            st.subheader("🔐 Login")
            
            user_type = st.selectbox("Login as:", ["Passenger", "Admin/Stakeholder"])
            username = st.text_input("Username:")
            password = st.text_input("Password:", type="password")
            
            if st.button("Login", type="primary"):
                if username.strip() and password.strip():
                    login_success, message = perform_login(username.strip(), password.strip(), user_type)
                    
                    if login_success:
                        user_data = st.session_state.users_db[username.strip()]

                        st.markdown(f"""
                        <div class="login-success">
                            <h4>✅ Login Successful!</h4>
                            <p>Welcome back, {user_data['name']}!</p>
                            <p>Role: {user_data.get('role_title', 'User')}</p>
                        </div>
                        """, unsafe_allow_html=True)
                        st.balloons()
                        time.sleep(1)  # Brief delay for user to see success message
                        st.rerun()
                    else:
                        st.error(f"❌ {message}")
                else:
                    st.error("❌ Please enter both username and password!")
            
            # Enhanced demo account information
            st.markdown("""
            <div class="environment-tip">
                <h4>🎯 Demo Accounts Available</h4>
            </div>
            """, unsafe_allow_html=True)
            
            st.info("""
            **⚙️ Admin/Stakeholder:**
            - Username: `admin` | Password: `admin123`
            - Username: `railway_officer` | Password: `officer123`
            
            **👥 Passenger:**
            - Username: `demo_user` | Password: `demo123`
            
            **Or register as a new user below!**
            """)
        
        else:
            st.subheader("📝 Register New User")
            with st.form("register_form"):
                user_type = st.selectbox("Register as:", ["Passenger", "Railway Officer", "Admin"])
                new_username = st.text_input("Username:", help="Choose a unique username")
                password = st.text_input("Password:", type="password", help="Choose a secure password")
                confirm_password = st.text_input("Confirm Password:", type="password")
                full_name = st.text_input("Full Name:")
                email = st.text_input("Email:")
                phone = st.text_input("Phone:")
                city = st.text_input("City:")
                
                submitted = st.form_submit_button("Register", type="primary")
                
                if submitted:
                    # Validation
                    errors = []
                    if not new_username.strip():
                        errors.append("Username is required")
                    elif new_username.strip() in st.session_state.users_db:
                        errors.append("Username already exists")
                    
                    if not password.strip():
                        errors.append("Password is required")
                    elif password != confirm_password:
                        errors.append("Passwords don't match")
                    
                    if not full_name.strip():
                        errors.append("Full name is required")
                    
                    if errors:
                        for error in errors:
                            st.error(f"❌ {error}")
                    else:
                        try:
                            role_mapping = {
                                "Passenger": "passenger",
                                "Railway Officer": "stakeholder", 
                                "Admin": "admin"
                            }
                            
                            new_user = {
                                "name": full_name.strip(),
                                "email": email.strip(),
                                "phone": phone.strip(),
                                "city": city.strip(),
                                "password": password.strip(),
                                "user_type": role_mapping[user_type],
                                "role_title": user_type,
                                "join_date": datetime.now().date().isoformat(),
                                "total_points": 0 if user_type == "Passenger" else None,
                                "level": 1 if user_type == "Passenger" else None,
                                "reports_count": 0,
                                "achievements": [],
                                "favorite_routes": []
                            }
                            
                            if user_type in ["Railway Officer", "Admin"]:
                                new_user.update({
                                    "is_admin": user_type == "Admin",
                                    "is_stakeholder": user_type == "Railway Officer",
                                    "employee_id": f"{user_type[:3].upper()}{len(st.session_state.users_db)+1:03d}",
                                    "department": "Operations" if user_type == "Railway Officer" else "Administration"
                                })
                            
                            st.session_state.users_db[new_username.strip()] = new_user
                            st.session_state.current_user = new_username.strip()
                            st.session_state.authenticated = True
                            
                            st.markdown(f"""
                            <div class="login-success">
                                <h4>✅ Registration Successful!</h4>
                                <p>Welcome to Swachh Score, {full_name}!</p>
                                <p>You are now logged in as: {user_type}</p>
                            </div>
                            """, unsafe_allow_html=True)
                            st.balloons()
                            time.sleep(2)  # Brief delay for user to see success message
                            st.rerun()
                            
                        except Exception as e:
                            st.error(f"❌ Registration failed: {str(e)}")

else:
    # Show current user info - Enhanced display
    current_user_data = st.session_state.users_db.get(st.session_state.current_user, {})
    user_role = current_user_data.get('user_type', 'passenger')
    role_title = current_user_data.get('role_title', 'Passenger')
    
    with st.sidebar:
        # Check for new notifications for passengers
        if user_role == 'passenger':
            user_notifications = get_user_notifications(st.session_state.current_user)
            unread_notifications = [n for n in user_notifications if not n.get('read', False)]
            
            if unread_notifications:
                st.markdown(f"""
                <div class="response-notification">
                    <h4>🔔 New Responses ({len(unread_notifications)})</h4>
                    <p>You have new responses from railway officials!</p>
                </div>
                """, unsafe_allow_html=True)
        
        # Enhanced user profile display
        st.markdown(f"""
<div class="success-animation">
    <h4>👋 Welcome, {current_user_data.get('name', 'User')}!</h4>
    <p><strong>Role:</strong> {role_title}</p>
    <p><strong>City:</strong> {current_user_data.get('city', 'N/A')}</p>
    {f"<p><strong>Level:</strong> {current_user_data.get('level', 'N/A')}</p>" if user_role == 'passenger' else ""}
    {f"<p><strong>Points:</strong> {current_user_data.get('total_points', 'N/A')}</p>" if user_role == 'passenger' else ""}
</div>
""", unsafe_allow_html=True)
        
        # Logout button with confirmation
        if st.button("🚪 Logout", type="secondary"):
            perform_logout()
            st.success("✅ Logged out successfully!")
            time.sleep(1)
            st.rerun()

# Navigation
st.sidebar.title("🎯 Navigation")

# Get user role safely
current_user_data = st.session_state.users_db.get(st.session_state.current_user, {}) if st.session_state.current_user else {}
user_role = current_user_data.get('user_type', 'guest') if st.session_state.authenticated else 'guest'
is_admin = user_role == 'admin'
is_stakeholder = user_role == 'stakeholder'

# Dynamic navigation based on user role
if st.session_state.authenticated and st.session_state.current_user:
    if user_role == 'passenger':
        nav_options = ["📊 Dashboard Overview", "📝 Report Issue", "🏆 Leaderboards", "📈 Analytics", "👤 My Profile", "🔔 My Notifications"]
    elif is_stakeholder:
        nav_options = ["📊 Dashboard Overview", "📋 Manage Reports", "📈 Analytics", "👤 My Profile"]
    elif is_admin:
        nav_options = ["📊 Dashboard Overview", "📝 Report Issue", "🏆 Leaderboards", "📈 Analytics", "👤 My Profile", "📋 Manage Reports", "⚙️ Admin Panel"]
    else:
        nav_options = ["📊 Dashboard Overview", "🏆 Leaderboards", "📈 Analytics"]
else:
    nav_options = ["📊 Dashboard Overview", "🏆 Leaderboards", "📈 Analytics"]

page = st.sidebar.selectbox("Choose a section:", nav_options)

# Dashboard Overview
if page == "📊 Dashboard Overview":
    # Environmental Impact Section
    st.markdown("""
    <div class="sustainability-banner">
        <h3>🌱 Environmental Impact Dashboard</h3>
        <p>Real-time insights from our community of environmental champions creating sustainable change!</p>
    </div>
    """, unsafe_allow_html=True)
    
    col1, col2, col3, col4 = st.columns(4)
    
    # Calculate metrics from real data
    if not df_stations.empty:
        avg_station_score = df_stations['cleanliness_score'].mean()
    else:
        avg_station_score = 8.2  # Default from sample data
    
    if not df_trains.empty:
        avg_train_score = df_trains['cleanliness_score'].mean()
    else:
        avg_train_score = 8.7  # Default from sample data
        
    total_reports = len(st.session_state.reports_db)
    active_users = len([u for u in st.session_state.users_db.values() if u.get('user_type') == 'passenger'])
    
    with col1:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-value">{avg_station_score:.1f}/10</div>
            <div class="metric-label">🚉 Avg Station Score</div>
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-value">{avg_train_score:.1f}/10</div>
            <div class="metric-label">🚆 Avg Train Score</div>
        </div>
        """, unsafe_allow_html=True)
    
    with col3:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-value">{total_reports:,}</div>
            <div class="metric-label">📋 Total Reports</div>
        </div>
        """, unsafe_allow_html=True)
    
    with col4:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-value">{active_users}</div>
            <div class="metric-label">👥 Eco Warriors</div>
        </div>
        """, unsafe_allow_html=True)
    
    # Show authentication status
    if st.session_state.authenticated:
        st.markdown(f"""
        <div class="environment-tip">
            <h4>✅ Welcome back!</h4>
            <p>You are logged in as <strong>{current_user_data.get('name', 'User')}</strong> ({role_title})</p>
            <p>Ready to contribute to a sustainable railway system! 🌱</p>
        </div>
        """, unsafe_allow_html=True)
    
    # Show real data trends
    if not df_reports.empty:
        st.subheader("📈 Recent Activity")
        
        # Recent reports timeline
        df_reports_copy = df_reports.copy()
        df_reports_copy['date'] = df_reports_copy['timestamp'].dt.date
        daily_reports = df_reports_copy.groupby('date').size().reset_index(name='Reports')
        
        if len(daily_reports) > 1:
            fig_timeline = px.line(daily_reports, x='date', y='Reports',
                                 title="Daily Reports Submitted",
                                 labels={'date': 'Date', 'Reports': 'Number of Reports'})
            fig_timeline.update_traces(line_color='#4CAF50', line_width=3)
            fig_timeline.update_layout(plot_bgcolor='rgba(0,0,0,0)')
            st.plotly_chart(fig_timeline, use_container_width=True)
        
        # Show recent reports
        st.subheader("📋 Recent Environmental Reports")
        recent_reports = df_reports.sort_values('timestamp', ascending=False).head(5)
        
        for _, report in recent_reports.iterrows():
            user_name = st.session_state.users_db.get(report['user'], {}).get('name', report['user'])
            status_colors = {"Open": "🔴", "In Progress": "🟡", "Resolved": "🟢"}
            status_color = status_colors.get(report['status'], '⚪')
            
            st.markdown(f"""
            <div class="report-card">
                <h4>{status_color} {report['location']} - {report['category']}</h4>
                <p><strong>Reporter:</strong> {user_name} | <strong>Severity:</strong> {report['severity']}</p>
                <p><strong>Description:</strong> {report['description'][:100]}...</p>
                <p><small>{report['timestamp'].strftime('%Y-%m-%d %H:%M')}</small></p>
            </div>
            """, unsafe_allow_html=True)
    else:
        st.info("📊 Welcome to the demo! Sample data is available to explore all features.")
        st.markdown("""
        <div class="environment-tip">
            <h4>🚀 Explore Features!</h4>
            <p>This dashboard includes sample data to demonstrate all functionalities. Register and start reporting to add your own data!</p>
        </div>
        """, unsafe_allow_html=True)

# Report Issue - Enhanced with better authentication check
elif page == "📝 Report Issue":
    st.header("📝 Report a Cleanliness Issue")
    
    if not st.session_state.authenticated or st.session_state.current_user is None:
        st.warning("⚠️ Please login to submit reports!")
        st.info("Use the sidebar to login with your credentials or register as a new user.")
        st.stop()
    
    # Verify user still exists in database
    if st.session_state.current_user not in st.session_state.users_db:
        st.error("❌ User session invalid. Please login again.")
        perform_logout()
        st.rerun()
    
    # Environmental awareness message
    st.markdown("""
    <div class="sustainability-banner">
        <h4>🌱 Make a Difference for Our Environment!</h4>
        <p>Every report you submit helps create a cleaner, more sustainable railway system. Your civic responsibility today ensures a better tomorrow for all.</p>
    </div>
    """, unsafe_allow_html=True)
    
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.subheader("Submit Your Report")
        
        report_type = st.selectbox("Report Type:", ["Station", "Train"])
        
        if report_type == "Station":
            station_options = ["New Delhi", "Mumbai Central", "Chennai Central", "Kolkata", "Bangalore City", "Hyderabad", "Pune", "Ahmedabad", "Jaipur", "Lucknow"]
            location = st.selectbox("Select Station:", station_options)
        else:
            train_options = ["Rajdhani Express (12001)", "Shatabdi Express (12002)", "Duronto Express (12005)", "Vande Bharat (22626)", "Gatimaan Express (12049)", "Jan Shatabdi (12023)"]
            location = st.selectbox("Select Train:", train_options)
        
        issue_category = st.selectbox(
            "Issue Category:",
            ["Toilets", "Platform/Coach Cleanliness", "Water Quality", 
             "Garbage Disposal", "Pest Control", "Overflowing Dustbin", "Food Court Hygiene", "Dirty drinking water points","Seat/Berth HYGIENE","Other"]
        )
        
        severity = st.select_slider(
            "Severity Level:",
            options=["Low", "Medium", "High", "Critical"],
            value="Medium"
        )
        
        description = st.text_area(
            "Describe the issue:",
            placeholder="Please provide detailed information about the cleanliness issue. Include location specifics, time of observation, and environmental impact...",
            height=100
        )
        
        # Image upload section
        st.markdown("""
        <div class="upload-area">
            <h4>📸 Upload Evidence (Optional)</h4>
            <p>Upload photos to earn bonus points (+5 points) and help authorities better understand the issue</p>
        </div>
        """, unsafe_allow_html=True)
        
        uploaded_image = st.file_uploader("Choose an image...", type=['png', 'jpg', 'jpeg'])
        
        if uploaded_image is not None:
            image = Image.open(uploaded_image)
            st.image(image, caption="Evidence Preview", width=300)
        
        if st.button("🚀 Submit Report", type="primary"):
            if not description.strip():
                st.error("❌ Please provide a description of the issue.")
            elif not location:
                st.error("❌ Please select a location.")
            else:
                try:
                    report = {
                        "timestamp": datetime.now(),
                        "type": report_type,
                        "location": location,
                        "category": issue_category,
                        "severity": severity,
                        "description": description.strip(),
                        "user": st.session_state.current_user,
                        "status": "Open",
                        "resolution_date": None,
                        "image": "uploaded" if uploaded_image else None
                    }
                    
                    if add_report(report):
                        points_earned = 10 + (5 if uploaded_image else 0)
                        report_id = f"RPT_{len(st.session_state.reports_db):04d}"
                        st.markdown(f"""
                        <div class="success-animation">
                            <h3>✅ Report Submitted Successfully!</h3>
                            <p>🎉 You earned {points_earned} points!</p>
                            <p>🌱 Thank you for contributing to a cleaner, more sustainable railway system!</p>
                            <p>Your civic responsibility helps protect our environment for future generations.</p>
                            <p>📋 Report ID: {report_id}</p>
                        </div>
                        """, unsafe_allow_html=True)
                        st.balloons()
                        time.sleep(2)
                        st.rerun()
                    else:
                        st.error("❌ Failed to submit report. Please try again.")
                        
                except Exception as e:
                    st.error(f"❌ Error submitting report: {str(e)}")
    
    with col2:
        st.markdown("""
        <div class="report-card">
            <h4>🎮 Gamification System</h4>
            <p><strong>Earn Points:</strong></p>
            <ul>
                <li>📝 Submit report: 10 points</li>
                <li>📸 Photo evidence: +5 points</li>
                <li>🔄 Follow-up: +3 points</li>
                <li>🌱 Environmental impact: +2 points</li>
            </ul>
        </div>
        """, unsafe_allow_html=True)
        
        # Show current user stats
        if st.session_state.authenticated and current_user_data:
            st.markdown(f"""
            <div class="metric-card">
                <h4>🏆 Your Stats</h4>
                <p><strong>Points:</strong> {current_user_data.get('total_points', 0)}</p>
                <p><strong>Level:</strong> {current_user_data.get('level', 1)}</p>
                <p><strong>Reports:</strong> {current_user_data.get('reports_count', 0)}</p>
                <p><strong>Environmental Impact:</strong> Making a difference! 🌱</p>
            </div>
            """, unsafe_allow_html=True)

# My Profile - Enhanced with better authentication checks
elif page == "👤 My Profile":
    if not st.session_state.authenticated or st.session_state.current_user is None:
        st.warning("⚠️ Please login to view your profile!")
        st.stop()
    
    # Verify user still exists
    if st.session_state.current_user not in st.session_state.users_db:
        st.error("❌ User session invalid. Please login again.")
        perform_logout()
        st.rerun()
    
    st.header("👤 My Profile")
    
    current_user_data = st.session_state.users_db.get(st.session_state.current_user, {})
    user_role = current_user_data.get('user_type', 'passenger')
    
    col1, col2 = st.columns([1, 1])
    
    with col1:
        st.subheader("📋 Personal Information")
        
        with st.form("profile_form"):
            name = st.text_input("Full Name:", value=current_user_data.get('name', ''))
            email = st.text_input("Email:", value=current_user_data.get('email', ''))
            phone = st.text_input("Phone:", value=current_user_data.get('phone', ''))
            city = st.text_input("City:", value=current_user_data.get('city', ''))
            
            if st.form_submit_button("💾 Update Profile", type="primary"):
                try:
                    st.session_state.users_db[st.session_state.current_user].update({
                        'name': name.strip(),
                        'email': email.strip(),
                        'phone': phone.strip(),
                        'city': city.strip()
                    })
                    st.success("✅ Profile updated successfully!")
                    time.sleep(1)
                    st.rerun()
                except Exception as e:
                    st.error(f"❌ Failed to update profile: {str(e)}")
    
    with col2:
        st.subheader("📊 Account Statistics")
        
        if user_role == 'passenger':
            achievements = current_user_data.get('achievements', [])
            st.markdown(f"""
            <div class="metric-card">
                <h4>🏆 Your Achievements</h4>
                <p><strong>Total Points:</strong> {current_user_data.get('total_points', 0)}</p>
                <p><strong>Current Level:</strong> {current_user_data.get('level', 1)}</p>
                <p><strong>Reports Submitted:</strong> {current_user_data.get('reports_count', 0)}</p>
                <p><strong>Join Date:</strong> {current_user_data.get('join_date', 'N/A')}</p>
                <p><strong>Achievements:</strong> {len(achievements)}</p>
            </div>
            """, unsafe_allow_html=True)
            
            # Show achievements
            if achievements:
                st.subheader("🏅 Achievements Unlocked")
                achievement_descriptions = {
                    "First Reporter": "🥇 Submitted your first environmental report",
                    "Eco Warrior": "🌱 Submitted 5+ environmental reports",
                    "Photo Detective": "📸 Included photo evidence in reports",
                    "Sustainability Champion": "🌍 Level 10+ environmental advocate"
                }
                
                for achievement in achievements:
                    description = achievement_descriptions.get(achievement, "🏆 Special achievement unlocked")
                    st.markdown(f"""
                    <div class="environment-tip">
                        <strong>{description}</strong>
                    </div>
                    """, unsafe_allow_html=True)
        else:
            st.markdown(f"""
            <div class="metric-card">
                <h4>👨‍💼 Staff Information</h4>
                <p><strong>Role:</strong> {current_user_data.get('role_title', 'Staff')}</p>
                <p><strong>Department:</strong> {current_user_data.get('department', 'N/A')}</p>
                <p><strong>Employee ID:</strong> {current_user_data.get('employee_id', 'N/A')}</p>
                <p><strong>Join Date:</strong> {current_user_data.get('join_date', 'N/A')}</p>
            </div>
            """, unsafe_allow_html=True)
    
    # Show user's reports
    if user_role == 'passenger':
        st.subheader("📋 My Reports History")
        user_reports = [r for r in st.session_state.reports_db if r.get('user') == st.session_state.current_user]
        
        if user_reports:
            for report in sorted(user_reports, key=lambda x: x.get('timestamp', datetime.now()), reverse=True):
                status_colors = {"Open": "🔴", "In Progress": "🟡", "Resolved": "🟢"}
                status_color = status_colors.get(report.get('status', 'Open'), '⚪')
                
                with st.expander(f"{status_color} {report.get('id', 'N/A')} - {report['location']} | {report['category']}"):
                    col_a, col_b = st.columns([2, 1])
                    
                    with col_a:
                        st.write(f"**📍 Location:** {report['location']} ({report['type']})")
                        st.write(f"**📂 Category:** {report['category']}")
                        st.write(f"**⚠️ Severity:** {report['severity']}")
                        st.write(f"**📅 Submitted:** {report['timestamp'].strftime('%Y-%m-%d %H:%M')}")
                        st.write(f"**📝 Description:** {report['description']}")
                        
                        if report.get('image'):
                            st.write("📸 Image Evidence: Attached")
                    
                    with col_b:
                        st.write(f"**Status:** {status_color} {report.get('status', 'Open')}")
                        if report.get('resolution_date'):
                            st.write(f"**Resolved:** {report['resolution_date'].strftime('%Y-%m-%d')}")
                    
                    # Show responses
                    responses = report.get('responses', [])
                    if responses:
                        st.write("---")
                        st.write("**🏛️ Official Responses:**")
                        for response in sorted(responses, key=lambda x: x['timestamp']):
                            st.markdown(f"""
                            <div class="admin-response">
                                <p><strong>👨‍💼 {response['responder_name']}</strong> - {response['timestamp'].strftime('%Y-%m-%d %H:%M')}</p>
                                <p>{response['response_text']}</p>
                                {f"<p><strong>Status Updated to:</strong> {response['status_update']}</p>" if response.get('status_update') else ""}
                            </div>
                            """, unsafe_allow_html=True)
        else:
            st.info("📝 No reports submitted yet. Start reporting to track your environmental impact!")

# My Notifications - Enhanced authentication
elif page == "🔔 My Notifications":
    if not st.session_state.authenticated or user_role != 'passenger':
        st.error("⚠️ This section is only available for logged-in passengers.")
        st.stop()
    
    st.header("🔔 My Notifications & Responses")
    
    st.markdown("""
    <div class="sustainability-banner">
        <h4>📢 Stay Updated with Official Responses!</h4>
        <p>Get real-time updates from railway officials about your environmental reports and their actions.</p>
    </div>
    """, unsafe_allow_html=True)
    
    user_notifications = get_user_notifications(st.session_state.current_user)
    
    if user_notifications:
        # Show unread notifications first
        unread_notifications = [n for n in user_notifications if not n.get('read', False)]
        read_notifications = [n for n in user_notifications if n.get('read', False)]
        
        if unread_notifications:
            st.subheader("🆕 New Responses")
            for notification in sorted(unread_notifications, key=lambda x: x['timestamp'], reverse=True):
                st.markdown(f"""
                <div class="response-notification">
                    <h4>📢 {notification['title']}</h4>
                    <p><strong>From:</strong> {notification['responder_name']}</p>
                    <p><strong>Message:</strong> {notification['message']}</p>
                    <p><small>Received: {notification['timestamp'].strftime('%Y-%m-%d %H:%M')}</small></p>
                </div>
                """, unsafe_allow_html=True)
                
                if st.button(f"✅ Mark as Read", key=f"read_{notification['id']}", type="secondary"):
                    mark_notification_as_read(notification['id'])
                    st.rerun()
        
        if read_notifications:
            st.subheader("📖 Previous Responses")
            with st.expander("View Previous Responses"):
                for notification in sorted(read_notifications, key=lambda x: x['timestamp'], reverse=True):
                    st.markdown(f"""
                    <div class="admin-response">
                        <h4>✅ {notification['title']}</h4>
                        <p><strong>From:</strong> {notification['responder_name']}</p>
                        <p><strong>Message:</strong> {notification['message']}</p>
                        <p><small>Received: {notification['timestamp'].strftime('%Y-%m-%d %H:%M')}</small></p>
                    </div>
                    """, unsafe_allow_html=True)
    else:
        st.info("🔔 No notifications yet. Submit reports to receive updates from railway officials!")
    
    # Show user's reports with responses
    st.subheader("📋 My Reports & Official Responses")
    user_reports = [r for r in st.session_state.reports_db if r.get('user') == st.session_state.current_user]
    
    if user_reports:
        for report in sorted(user_reports, key=lambda x: x.get('timestamp', datetime.now()), reverse=True):
            status_colors = {"Open": "🔴", "In Progress": "🟡", "Resolved": "🟢"}
            status_color = status_colors.get(report.get('status', 'Open'), '⚪')
            
            with st.expander(f"{status_color} {report.get('id', 'N/A')} - {report['location']} | {report['category']}"):
                col1, col2 = st.columns([2, 1])
                
                with col1:
                    st.write(f"**📍 Location:** {report['location']} ({report['type']})")
                    st.write(f"**📂 Category:** {report['category']}")
                    st.write(f"**⚠️ Severity:** {report['severity']}")
                    st.write(f"**📅 Submitted:** {report['timestamp'].strftime('%Y-%m-%d %H:%M')}")
                    st.write(f"**📝 Description:** {report['description']}")
                    
                    if report.get('image'):
                        st.write("📸 Image Evidence: Attached")
                
                with col2:
                    st.write(f"**Status:** {status_color} {report.get('status', 'Open')}")
                    if report.get('resolution_date'):
                        st.write(f"**Resolved:** {report['resolution_date'].strftime('%Y-%m-%d')}")
                
                # Show responses from officials
                responses = report.get('responses', [])
                if responses:
                    st.write("---")
                    st.write("**🏛️ Official Responses:**")
                    for response in sorted(responses, key=lambda x: x['timestamp']):
                        st.markdown(f"""
                        <div class="admin-response">
                            <p><strong>👨‍💼 {response['responder_name']}</strong> - {response['timestamp'].strftime('%Y-%m-%d %H:%M')}</p>
                            <p>{response['response_text']}</p>
                            {f"<p><strong>Status Updated to:</strong> {response['status_update']}</p>" if response.get('status_update') else ""}
                        </div>
                        """, unsafe_allow_html=True)
                else:
                    st.info("⏳ Waiting for official response...")
    else:
        st.info("📝 No reports submitted yet. Start reporting to track responses!")

# Manage Reports - Enhanced authentication
elif page == "📋 Manage Reports":
    if not (is_stakeholder or is_admin):
        st.error("🚫 Access denied. Stakeholder or Admin privileges required.")
        st.info("Please login with appropriate credentials to access this section.")
        st.stop()
    
    st.header("📋 Environmental Report Management System")
    
    st.markdown("""
    <div class="sustainability-banner">
        <h4>🌱 Sustainable Operations Management</h4>
        <p>Efficiently manage environmental reports and provide responses to ensure swift action and sustainable solutions.</p>
    </div>
    """, unsafe_allow_html=True)
    
    if not st.session_state.reports_db:
        st.info("📊 No reports to manage yet. Sample data is available for demonstration.")
        st.stop()
    
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.subheader("📊 Reports Overview")
        
        # Filter controls
        col_a, col_b, col_c = st.columns(3)
        
        with col_a:
            status_filter = st.selectbox("Filter by Status:", ["All", "Open", "In Progress", "Resolved"])
        with col_b:
            severity_filter = st.selectbox("Filter by Severity:", ["All", "Low", "Medium", "High", "Critical"])
        with col_c:
            days_filter = st.selectbox("Time Period:", ["All Time", "Last 7 days", "Last 30 days"])
        
        # Apply filters
        filtered_reports = df_reports.copy() if not df_reports.empty else pd.DataFrame()
        
        if not filtered_reports.empty:
            if status_filter != "All":
                filtered_reports = filtered_reports[filtered_reports['status'] == status_filter]
            
            if severity_filter != "All":
                filtered_reports = filtered_reports[filtered_reports['severity'] == severity_filter]
            
            if days_filter != "All Time":
                days_map = {"Last 7 days": 7, "Last 30 days": 30}
                cutoff_date = datetime.now() - timedelta(days=days_map[days_filter])
                filtered_reports = filtered_reports[filtered_reports['timestamp'] >= cutoff_date]
        
        st.write(f"**{len(filtered_reports) if not filtered_reports.empty else 0} environmental reports found**")
        
        # Display filtered reports with response functionality
        if not filtered_reports.empty:
            for _, report in filtered_reports.sort_values('timestamp', ascending=False).iterrows():
                user_name = st.session_state.users_db.get(report['user'], {}).get('name', report['user'])
                status_colors = {"Open": "🔴", "In Progress": "🟡", "Resolved": "🟢"}
                status_color = status_colors.get(report['status'], '⚪')
                severity_colors = {"Low": "🟢", "Medium": "🟡", "High": "🟠", "Critical": "🔴"}
                severity_color = severity_colors.get(report['severity'], '⚪')
                
                with st.expander(f"{status_color} {report.get('id', 'N/A')} - {report['location']} | {severity_color} {report['severity']}"):
                    col_x, col_y = st.columns([2, 1])
                    
                    with col_x:
                        st.write(f"**👤 Reporter:** {user_name}")
                        st.write(f"**📍 Location:** {report['location']} ({report['type']})")
                        st.write(f"**📂 Category:** {report['category']}")
                        st.write(f"**📅 Date:** {report['timestamp'].strftime('%Y-%m-%d %H:%M')}")
                        st.write(f"**📝 Description:** {report['description']}")
                        st.write(f"**🌱 Environmental Priority:** {report['severity']}")
                        
                        if report.get('image'):
                            st.write("📸 Image Evidence Available")
                        
                        # Show existing responses
                        responses = report.get('responses', [])
                        if responses:
                            st.write("---")
                            st.write("**Previous Responses:**")
                            for response in responses:
                                st.markdown(f"""
                                <div class="admin-response" style="margin: 0.5rem 0; padding: 0.8rem;">
                                    <p><strong>{response['responder_name']}</strong> - {response['timestamp'].strftime('%Y-%m-%d %H:%M')}</p>
                                    <p>{response['response_text']}</p>
                                    {f"<p><small>Status: {response['status_update']}</small></p>" if response.get('status_update') else ""}
                                </div>
                                """, unsafe_allow_html=True)
                    
                    with col_y:
                        st.write("**⚙️ Actions:**")
                        
                        new_status = st.selectbox(
                            "Update Status:",
                            ["Open", "In Progress", "Resolved"],
                            index=["Open", "In Progress", "Resolved"].index(report['status']),
                            key=f"status_{report.get('id', 'temp')}"
                        )
                        
                        response_text = st.text_area(
                            "Your Response to Passenger:",
                            placeholder="Describe the action taken, timeline, or further instructions...",
                            key=f"response_{report.get('id', 'temp')}",
                            height=100
                        )
                        
                        if st.button("📤 Send Response & Update", key=f"update_{report.get('id', 'temp')}", type="primary"):
                            if response_text.strip():
                                success = add_response_to_report(
                                    report.get('id'), 
                                    st.session_state.current_user, 
                                    response_text.strip(),
                                    new_status if new_status != report['status'] else None
                                )
                                
                                if success:
                                    st.success("✅ Response sent to passenger successfully!")
                                    time.sleep(1)
                                    st.rerun()
                                else:
                                    st.error("❌ Failed to send response.")
                            else:
                                st.error("Please enter a response message.")
        else:
            st.info("No reports match the current filters.")
    
    with col2:
        st.subheader("📈 Quick Stats")
        
        if st.session_state.reports_db:
            status_counts = df_reports['status'].value_counts() if not df_reports.empty else pd.Series()
            for status, count in status_counts.items():
                status_colors = {"Open": "🔴", "In Progress": "🟡", "Resolved": "🟢"}
                status_color = status_colors.get(status, '⚪')
                st.metric(f"{status_color} {status}", count)
            
            st.subheader("🌿 Recent Activity")
            recent = df_reports.sort_values('timestamp', ascending=False).head(5) if not df_reports.empty else pd.DataFrame()
            if not recent.empty:
                for _, report in recent.iterrows():
                    user_name = st.session_state.users_db.get(report['user'], {}).get('name', report['user'])
                    st.write(f"🌱 **{user_name}** - {report['location']}")
                    st.write(f"   _{report['timestamp'].strftime('%m/%d %H:%M')}_")

# Admin Panel - Enhanced authentication
elif page == "⚙️ Admin Panel":
    if not is_admin:
        st.error("🚫 Access denied. Admin privileges required.")
        st.info("Please login with admin credentials to access this section.")
        st.stop()
    
    st.header("⚙️ System Administration Panel")
    
    st.markdown("""
    <div class="admin-panel">
        <h3>🔧 Administrative Controls</h3>
        <p>Complete system management for Swachh Score Railway Dashboard</p>
    </div>
    """, unsafe_allow_html=True)
    
    tab1, tab2, tab3, tab4 = st.tabs(["👥 User Management", "📊 System Analytics", "🗂️ Data Management", "⚙️ System Settings"])
    
    with tab1:
        st.subheader("👥 User Management")
        
        col1, col2 = st.columns([2, 1])
        
        with col1:
            st.write("**All Registered Users:**")
            users_data = []
            for username, user_info in st.session_state.users_db.items():
                users_data.append({
                    "Username": username,
                    "Name": user_info.get('name', 'N/A'),
                    "Role": user_info.get('role_title', 'N/A'),
                    "City": user_info.get('city', 'N/A'),
                    "Join Date": user_info.get('join_date', 'N/A'),
                    "Reports": user_info.get('reports_count', 0),
                    "Points": user_info.get('total_points', 'N/A')
                })
            
            users_df = pd.DataFrame(users_data)
            st.dataframe(users_df, use_container_width=True)
        
        with col2:
            st.write("**User Statistics:**")
            total_users = len(st.session_state.users_db)
            passengers = len([u for u in st.session_state.users_db.values() if u.get('user_type') == 'passenger'])
            staff = total_users - passengers
            
            st.metric("Total Users", total_users)
            st.metric("Passengers", passengers)
            st.metric("Staff/Admin", staff)
            
            # User role distribution pie chart
            if total_users > 0:
                role_data = {"Passengers": passengers, "Staff/Admin": staff}
                fig_roles = px.pie(values=list(role_data.values()), names=list(role_data.keys()),
                                  title="User Role Distribution")
                st.plotly_chart(fig_roles, use_container_width=True)
    
    with tab2:
        st.subheader("📊 System Analytics Dashboard")
        
        # System performance metrics
        col1, col2, col3, col4 = st.columns(4)
        
        total_reports = len(st.session_state.reports_db)
        resolved_reports = len([r for r in st.session_state.reports_db if r.get('status') == 'Resolved'])
        response_rate = (len([r for r in st.session_state.reports_db if r.get('responses', [])]) / max(total_reports, 1)) * 100
        avg_resolution_time = "2.3 days"  # Sample data
        
        with col1:
            st.metric("Total Reports", total_reports)
        with col2:
            st.metric("Resolved Reports", resolved_reports)
        with col3:
            st.metric("Response Rate", f"{response_rate:.1f}%")
        with col4:
            st.metric("Avg Resolution Time", avg_resolution_time)
        
        # System usage analytics
        if not df_reports.empty:
            st.subheader("📈 Usage Analytics")
            
            # Reports by category
            category_stats = df_reports['category'].value_counts()
            fig_categories = px.bar(x=category_stats.values, y=category_stats.index,
                                   orientation='h', title="Reports by Category")
            st.plotly_chart(fig_categories, use_container_width=True)
            
            # Reports by severity
            severity_stats = df_reports['severity'].value_counts()
            fig_severity = px.pie(values=severity_stats.values, names=severity_stats.index,
                                 title="Reports by Severity Level")
            st.plotly_chart(fig_severity, use_container_width=True)
    
    with tab3:
        st.subheader("🗂️ Data Management")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.write("**Export System Data:**")
            
            if st.button("📥 Export All Data (JSON)", type="primary"):
                try:
                    export_json = export_data()
                    st.download_button(
                        label="⬇️ Download Data Export",
                        data=export_json,
                        file_name=f"swachh_score_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                        mime="application/json"
                    )
                    st.success("✅ Data export ready for download!")
                except Exception as e:
                    st.error(f"❌ Export failed: {e}")
            
            st.write("**Database Statistics:**")
            st.write(f"- **Users:** {len(st.session_state.users_db)} records")
            st.write(f"- **Reports:** {len(st.session_state.reports_db)} records")
            st.write(f"- **Stations:** {len(st.session_state.stations_db)} records")
            st.write(f"- **Trains:** {len(st.session_state.trains_db)} records")
            st.write(f"- **Notifications:** {len(st.session_state.notifications_db)} records")
        
        with col2:
            st.write("**System Maintenance:**")
            
            if st.button("🧹 Clear Old Notifications (30+ days)", type="secondary"):
                old_notifications = [n for n in st.session_state.notifications_db 
                                   if (datetime.now() - n.get('timestamp', datetime.now())).days > 30]
                if old_notifications:
                    st.session_state.notifications_db = [n for n in st.session_state.notifications_db 
                                                       if (datetime.now() - n.get('timestamp', datetime.now())).days <= 30]
                    st.success(f"✅ Cleaned {len(old_notifications)} old notifications")
                else:
                    st.info("No old notifications to clean")
            
            if st.button("📊 Recalculate User Stats", type="secondary"):
                for username, user_data in st.session_state.users_db.items():
                    if user_data.get('user_type') == 'passenger':
                        user_reports = [r for r in st.session_state.reports_db if r.get('user') == username]
                        user_data['reports_count'] = len(user_reports)
                        # Recalculate points based on reports
                        total_points = 0
                        for report in user_reports:
                            total_points += 10  # Base points
                            if report.get('image'):
                                total_points += 5  # Photo bonus
                        user_data['total_points'] = total_points
                        user_data['level'] = total_points // 50 + 1
                st.success("✅ User statistics recalculated")
                st.rerun()
    
    with tab4:
        st.subheader("⚙️ System Settings")
        
        st.write("**Application Configuration:**")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.write("**Point System Settings:**")
            base_points = st.number_input("Base Report Points:", value=10, min_value=1, max_value=50)
            photo_bonus = st.number_input("Photo Evidence Bonus:", value=5, min_value=0, max_value=20)
            level_threshold = st.number_input("Points per Level:", value=50, min_value=10, max_value=200)
            
            if st.button("💾 Save Point Settings"):
                st.success("✅ Point system settings saved!")
                # Note: In a real app, these would be stored in a config file or database
        
        with col2:
            st.write("**System Information:**")
            st.write(f"- **Version:** 2.0.0")
            st.write(f"- **Last Updated:** {datetime.now().strftime('%Y-%m-%d')}")
            st.write(f"- **Database Size:** ~{len(str(st.session_state))} characters")
            st.write(f"- **Active Users:** {len([u for u in st.session_state.users_db.values() if u.get('user_type') == 'passenger'])}")
            
            if st.button("🔄 Reset Demo Data"):
                if st.checkbox("I understand this will reset all data"):
                    # Reset to initial state with sample data
                    for key in ['users_db', 'reports_db', 'stations_db', 'trains_db', 'notifications_db', 'initialized']:
                        if key in st.session_state:
                            del st.session_state[key]
                    perform_logout()
                    initialize_session_state()
                    st.success("✅ Demo data has been reset!")
                    time.sleep(1)
                    st.rerun()

# Leaderboards
elif page == "🏆 Leaderboards":
    st.header("🏆 Sustainability Champions Leaderboard")
    
    st.markdown("""
    <div class="sustainability-banner">
        <h4>🌟 Celebrating Our Environmental Heroes!</h4>
        <p>These champions are leading the way in creating a cleaner, more sustainable railway system through their civic sense and environmental consciousness.</p>
    </div>
    """, unsafe_allow_html=True)
    
    tab1, tab2, tab3 = st.tabs(["🚉 Stations", "🚆 Trains", "👥 Eco Warriors"])
    
    with tab1:
        st.subheader("🌱 Station Sustainability Rankings")
        if not df_stations.empty:
            station_scores = df_stations.groupby('station')['cleanliness_score'].agg(['mean', 'count']).reset_index()
            station_scores.columns = ['Station', 'Environmental Score', 'Reports Count']
            station_scores = station_scores.sort_values('Environmental Score', ascending=False).reset_index(drop=True)
            station_scores.index += 1
            
            if len(station_scores) > 0:
                st.dataframe(station_scores, use_container_width=True)
                
                if len(station_scores) > 1:
                    fig_stations = px.bar(station_scores.head(10), x='Station', y='Environmental Score',
                                          title="Most Sustainable Stations",
                                          color='Environmental Score',
                                          color_continuous_scale='Greens')
                    fig_stations.update_layout(xaxis_tickangle=-45, plot_bgcolor='rgba(0,0,0,0)')
                    st.plotly_chart(fig_stations, use_container_width=True)
            else:
                st.info("No station data available yet.")
        else:
            st.info("📊 No station data available.")
    
    with tab2:
        st.subheader("🚆 Train Sustainability Rankings")
        if not df_trains.empty: # You were missing an if/else block for trains. I've added a placeholder check.
            train_scores = df_trains.groupby('train_name')['cleanliness_score'].agg(['mean', 'count']).reset_index()
            train_scores.columns = ['Train', 'Environmental Score', 'Reports Count']
            train_scores = train_scores.sort_values('Environmental Score', ascending=False).reset_index(drop=True)
            train_scores.index += 1
            
            if len(train_scores) > 0:
                st.dataframe(train_scores, use_container_width=True)
                
                if len(train_scores) > 1:
                    fig_trains = px.bar(train_scores.head(10), x='Train', y='Environmental Score',
                                        title="Most Sustainable Trains",
                                        color='Environmental Score',
                                        color_continuous_scale='Greens')
                    fig_trains.update_layout(xaxis_tickangle=-45, plot_bgcolor='rgba(0,0,0,0)')
                    st.plotly_chart(fig_trains, use_container_width=True)
            else:
                st.info("No train data available yet.")
        else:
            # Show sample train rankings
            st.info("📊 No train data available.")
            sample_trains = [
                {"rank": 1, "name": "Vande Bharat", "number": "22626", "route": "Delhi - Varanasi", "score": 9.3, "reports": 8},
                {"rank": 2, "name": "Shatabdi Express", "number": "12002", "route": "New Delhi - Chandigarh", "score": 9.1, "reports": 12},
                {"rank": 3, "name": "Rajdhani Express", "number": "12001", "route": "New Delhi - Mumbai", "score": 8.4, "reports": 25},
                {"rank": 4, "name": "Duronto Express", "number": "12005", "route": "Mumbai - Delhi", "score": 7.8, "reports": 18}
            ]
            
            for train in sample_trains:
                medal = "🥇" if train['rank'] == 1 else "🥈" if train['rank'] == 2 else "🥉" if train['rank'] == 3 else "🌟"
                eco_rating = "🌱🌱🌱" if train['score'] >= 9 else "🌱🌱" if train['score'] >= 8 else "🌱"
                st.markdown(f"""
                <div class="report-card">
                    <h4>{medal} #{train['rank']} - {train['name']} ({train['number']})</h4>
                    <p><strong>Route:</strong> {train['route']}</p>
                    <p><strong>Sustainability Score:</strong> {train['score']}/10 {eco_rating}</p>
                    <p><strong>Community Reports:</strong> {train['reports']}</p>
                </div>
                """, unsafe_allow_html=True)

    with tab3:
        st.subheader("🌟 Environmental Champions")
        if st.session_state.users_db:
            passenger_users = [(k, v) for k, v in st.session_state.users_db.items() 
                             if v.get('user_type') == 'passenger' and v.get('total_points', 0) > 0]
            
            if passenger_users:
                user_rankings = sorted(passenger_users, key=lambda x: x[1].get('total_points', 0), reverse=True)
                
                for i, (username, user_data) in enumerate(user_rankings, 1):
                    medal = "🥇" if i == 1 else "🥈" if i == 2 else "🥉" if i == 3 else "🌟"
                    eco_title = "🌍 Planet Protector" if user_data.get('total_points', 0) >= 200 else "🌱 Eco Warrior" if user_data.get('total_points', 0) >= 100 else "🌿 Green Guardian"
                    st.markdown(f"""
                    <div class="report-card">
                        <h4>{medal} #{i} - {user_data.get('name', username)} {eco_title}</h4>
                        <p><strong>Environmental Points:</strong> {user_data.get('total_points', 0)} | 
                        <strong>Level:</strong> {user_data.get('level', 1)} | 
                        <strong>Reports:</strong> {user_data.get('reports_count', 0)}</p>
                        <p><strong>City:</strong> {user_data.get('city', 'N/A')}</p>
                        <p><strong>Impact:</strong> Contributing to a sustainable future! 🌱</p>
                    </div>
                    """, unsafe_allow_html=True)
            else:
                st.info("🏆 No environmental champions yet! Be the first to report and earn points!")

# Analytics
elif page == "📈 Analytics":
    st.header("📈 Environmental Impact Analytics")
    
    st.markdown("""
    <div class="sustainability-banner">
        <h4>📊 Data-Driven Environmental Insights</h4>
        <p>Understanding patterns in cleanliness reporting helps us build more sustainable and efficient railway systems.</p>
    </div>
    """, unsafe_allow_html=True)
    
    if not df_reports.empty:
        st.subheader("📊 Environmental Issue Categories")
        
        col1, col2 = st.columns(2)
        
        with col1:
            category_counts = df_reports['category'].value_counts()
            fig_categories = px.pie(values=category_counts.values, names=category_counts.index,
                                    title="Distribution of Environmental Issues",
                                    color_discrete_sequence=px.colors.qualitative.Set3)
            st.plotly_chart(fig_categories, use_container_width=True)
        
        with col2:
            severity_counts = df_reports['severity'].value_counts()
            fig_severity = px.bar(x=severity_counts.index, y=severity_counts.values,
                                  title="Environmental Impact Severity",
                                  labels={'x': 'Severity Level', 'y': 'Count'},
                                  color=severity_counts.values,
                                  color_continuous_scale='RdYlGn_r')
            fig_severity.update_layout(plot_bgcolor='rgba(0,0,0,0)')
            st.plotly_chart(fig_severity, use_container_width=True)
        
        # Environmental impact timeline
        df_reports_copy = df_reports.copy()
        df_reports_copy['date'] = df_reports_copy['timestamp'].dt.date
        daily_reports = df_reports_copy.groupby('date').size().reset_index(name='count')
        
        if len(daily_reports) > 1:
            fig_timeline = px.area(daily_reports, x='date', y='count',
                                     title="Community Environmental Reporting Over Time")
            fig_timeline.update_traces(fill='tonexty', fillcolor='rgba(76, 175, 80, 0.3)')
            fig_timeline.update_layout(plot_bgcolor='rgba(0,0,0,0)')
            st.plotly_chart(fig_timeline, use_container_width=True)
        
        # Status distribution
        st.subheader("📈 Report Resolution Status")
        status_counts = df_reports['status'].value_counts()
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.metric("🔴 Open Reports", status_counts.get('Open', 0))
        with col2:
            st.metric("🟡 In Progress", status_counts.get('In Progress', 0))
        with col3:
            st.metric("🟢 Resolved", status_counts.get('Resolved', 0))
        
        # Response rate analytics
        if st.session_state.reports_db:
            reports_with_responses = len([r for r in st.session_state.reports_db if r.get('responses', [])])
            response_rate = (reports_with_responses / len(st.session_state.reports_db)) * 100
            
            st.subheader("📢 Communication Effectiveness")
            st.metric("Response Rate", f"{response_rate:.1f}%", f"{reports_with_responses}/{len(st.session_state.reports_db)} reports")
    else:
        st.info("📊 Demo analytics with sample data visualization!")
        
        # Show sample analytics with demo data
        st.subheader("📊 Sample Environmental Impact Analysis")
        
        col1, col2 = st.columns(2)
        
        with col1:
            # Sample category distribution
            sample_categories = ["Toilets", "Platform/Coach Cleanliness", "Water Quality", "Garbage Disposal", "Air Quality"]
            sample_counts = [8, 6, 4, 3, 2]
            fig_sample_cat = px.pie(values=sample_counts, names=sample_categories,
                                    title="Sample Issue Categories Distribution")
            st.plotly_chart(fig_sample_cat, use_container_width=True)
        
        with col2:
            # Sample severity distribution
            sample_severity = ["High", "Medium", "Critical", "Low"]
            severity_counts = [7, 9, 3, 4]
            fig_sample_sev = px.bar(x=sample_severity, y=severity_counts,
                                    title="Sample Severity Distribution",
                                    color=severity_counts,
                                    color_continuous_scale='RdYlGn_r')
            st.plotly_chart(fig_sample_sev, use_container_width=True)
        
        st.markdown("""
        <div class="environment-tip">
            <h4>📈 Start Reporting for Real Analytics!</h4>
            <p>Once you start submitting reports, you'll see:</p>
            <ul>
                <li>📊 Real issue category distributions</li>
                <li>📈 Actual reporting trends over time</li>
                <li>🏆 Live station performance rankings</li>
                <li>📢 Real response rate analytics</li>
                <li>🌱 Your environmental impact metrics</li>
            </ul>
        </div>
        """, unsafe_allow_html=True)
    
    # Environmental impact metrics
    st.subheader("🌍 Environmental Impact Summary")
    total_reports = len(st.session_state.reports_db)
    resolved_reports = len([r for r in st.session_state.reports_db if r.get('status') == 'Resolved'])
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("🌱 Environmental Reports", total_reports, "Community driven")
    with col2:
        st.metric("✅ Issues Resolved", resolved_reports, f"{(resolved_reports/max(total_reports,1)*100):.1f}% resolved")
    with col3:
        carbon_saved = total_reports * 2.5 # Sample calculation
        st.metric("🌍 Est. Carbon Impact", f"{carbon_saved:.1f} kg CO₂", "Saved through reporting")
    with col4:
        sustainability_score = min(100, (resolved_reports / max(total_reports, 1)) * 100 + 20)
        st.metric("♻️ Sustainability Index", f"{sustainability_score:.1f}/100", "System health")

# Footer
st.markdown("---")
st.markdown("""
<div style="text-align: center; padding: 2rem; background: linear-gradient(135deg, #4CAF50 0%, #2E7D32 100%); border-radius: 15px; margin-top: 2rem;">
    <h3 style="color: white; margin: 0;">🌱 Together for a Sustainable Future</h3>
    <p style="color: white; margin: 0.5rem 0 0 0; opacity: 0.9;">
        Every report contributes to a cleaner, greener Indian Railway system. Thank you for being an environmental champion!
    </p>
</div>
""", unsafe_allow_html=True)
st.markdown("""
<div style="text-align: center; padding: 1rem; margin-top: 2rem; background: #FA5B3E; color: white; border-radius: 8px;">
    <img src="https://upload.wikimedia.org/wikipedia/en/thumb/8/83/Indian_Railways.svg/1200px-Indian_Railways.svg.png" style="height:40px;">
    <p style="margin:0;">Indian Railways - Swachh Rail Initiative</p>
</div>
""", unsafe_allow_html=True)