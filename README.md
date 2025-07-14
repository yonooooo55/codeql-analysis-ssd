# Co-Curricular Activities Portal (CCAP))
The Co-Curricular Activities Portal (CCAP) is a secure web application designed to democratize decision-making within student organizations at SIT. The platform enables:

- **Students** to participate in important CCA decisions through secure, anonymous voting on matters such as scheduling and leadership selection
- **Moderators** (student leaders) to create polls, manage members, and collect feedback from their CCA community
- **Administrators** to oversee all CCAs, assign moderator roles, and maintain the integrity of the platform

## Team Members
| Name  | Student ID |
| ------------- | ------------- |
| Glenn Tham Guoxiang | 2301803  |
| Dominic Loh Rui Jie  | 2301823  |
| Khoo Ye Chen | 2301821  |
| Nathaneal Ambrose Goh Kian Seng  | 2302094  |
| Chow Yu Tong Emi | 2302092  |
| Tan Ying Xuan Shermaine  | 2303512  |
| Low Shao Qi  | 2303294  |

## Features
- **Multi-Role Authentication**: Secure role-based access control for Administrators, Moderators, and Students 
- **Anonymous Voting System**: Secure, tamper-proof polling with optional anonymity  
- **Real-time Results**: Live poll statistics and result representations 
- **CCA Management**: Complete lifecycle management of CCAs and member assignments 
- **Email Notifications**: Automated email notifications for new users to set their own passwords and activate access
- **Session Security**: Advanced session management with timeout and hijacking protection

## Architecture
- **Backend**: Flask (Python 3.8+)
- **Database**: Azure SQL Database
- **Frontend**: HTML5, CSS3, JavaScript
- **Session Management**: Flask-Session with SQLAlchemy backend
- **Email Service**: Flask-Mail with SMTP
- **Security**: bcrypt, pyotp, Google reCAPTCHA
- **Containerization**: Docker with NGINX reverse proxy

## Project Structure
```
ICT2216-Group1-CCAPortal/
├── application/           
│   ├── admin_routes.py       # Administrator functionality
│   ├── moderator_routes.py   # Moderator functionality
│   ├── student_routes.py     # Student functionality
│   ├── misc_routes.py        # Authentication & misc routes
│   ├── auth_utils.py         # Authentication utilities
│   ├── captcha_utils.py      # CAPTCHA validation
│   └── models.py             # Database models
├── .github/workflows/        # CI/CD pipelines
├── docker/                   # Docker configuration
├── nginx/                    # NGINX configuration
├── static/                   # Static assets (CSS, JS, images)
├── templates/                # Jinja2 templates
├── tests/                    # Automated test suite
├── logs/                     # Application logs
├── app.py                    # Main Flask application
├── config.py                 # Configuration settings
├── email_service.py          # Email service handler
└── requirements.txt          # Python dependencies
```

## Quick Start

### Try the Live Demo
Visit **[https://ccap-app.domloh.com/](https://ccap-app.domloh.com/)** to experience the application without any setup required.

### Prerequisites for Local Development
- Python 3.8 or higher
- pip (Python package installer)
- Git
- Docker (optional, for containerized deployment)

### Local Development

#### 1. Clone the repository
   ```
   git clone https://github.com/glenngx/ICT2216-Group1-CCAPortal.git
   cd ICT2216-Group1-CCAPortal
   ```
   
#### 2. Create and activate virtual environment
   ```
   python -m venv venv
   
   On Windows:
   venv\Scripts\activate
   
   On macOS/Linux:
   source venv/bin/activate
   ```
   
#### 3. Install dependencies
   ```
   pip install -r requirements.txt
   ```

#### 4. Environment Configuration
   Create .env file in root directory
   ```
   # Gmail SMTP Settings
   MAIL_SERVER=smtp.gmail.com
   MAIL_PORT=587
   MAIL_USE_TLS=True
   MAIL_USE_SSL=False
   
   # Your email credentials
   MAIL_USERNAME=your-email@gmail.com
   MAIL_PASSWORD=your-app-password
   
   # Default sender
   MAIL_DEFAULT_SENDER=your-email@gmail.com
   
   # Application settings
   ADMIN_EMAIL=admin@yourdomain.com
   SITE_NAME=CCA Portal
   SITE_URL=http://localhost:5000
   
   # Google reCAPTCHA settings
   RECAPTCHA_SITE_KEY=your-recaptcha-site-key
   RECAPTCHA_SECRET=your-recaptcha-secret-key
   ```
   
#### 5. Application Configuration
   Create config.py file in root directory
   ```
   import os
   
   class Config:
       # Database Configuration
       DB_DRIVER = "ODBC Driver 18 for SQL Server"
       DB_SERVER = "tcp:your-server.database.windows.net,1433"  
       DB_NAME = "your-database-name"                          
       DB_USER = "your-username"                            
       DB_PASSWORD = "your-password"
       DB_CONNECTION_STRING = f"DRIVER={{{DB_DRIVER}}};SERVER={DB_SERVER};DATABASE={DB_NAME};UID={DB_USER};PWD={DB_PASSWORD};
       Encrypt=yes;TrustServerCertificate=yes;Connection Timeout=30;"
       
       # Flask Configuration
       SECRET_KEY = "your-secret-key-here"
       
       # Email Configuration 
       MAIL_SERVER = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
       MAIL_PORT = int(os.environ.get('MAIL_PORT', 587))
       MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS', 'True').lower() == 'true'
       MAIL_USE_SSL = os.environ.get('MAIL_USE_SSL', 'False').lower() == 'true'
       MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
       MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
       MAIL_DEFAULT_SENDER = os.environ.get('MAIL_DEFAULT_SENDER', MAIL_USERNAME)
       
       # Application Settings
       ADMIN_EMAIL = os.environ.get('ADMIN_EMAIL', 'admin@yourdomain.com')
       SITE_NAME = 'CCA Portal'
       SITE_URL = os.environ.get('SITE_URL', 'http://localhost:5000')
       
       # Token expiration
       PASSWORD_RESET_TOKEN_EXPIRE = 24 * 60 * 60
       
       # Flask Settings
       DEBUG = True  
       
       # SQLAlchemy Configuration
       SQLALCHEMY_DATABASE_URI = f"mssql+pyodbc://{DB_USER}:{DB_PASSWORD}@{DB_SERVER.replace('tcp:', '')}/
       {DB_NAME}?driver={DB_DRIVER.replace(' ', '+')}"
       SQLALCHEMY_TRACK_MODIFICATIONS = False
   ```
   
#### 6. Run the application
   ```
   python app.py
   ```

#### 7. Access the application at http://localhost:5000
