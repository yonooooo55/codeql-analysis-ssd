from flask import current_app, url_for
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
import logging

class EmailService:
    def __init__(self, app=None):
        self.mail = None
        self.serializer = None
        if app:
            self.init_app(app)
    
    def init_app(self, app):
        """Initialize the email service with Flask app"""
        self.mail = Mail(app)
        self.serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    
    def generate_password_reset_token(self, student_id):
        """Generate a secure token for password reset"""
        data = {
            'student_id': student_id,
            'action': 'password_reset'
        }
        return self.serializer.dumps(data)
    
    def verify_password_reset_token(self, token, max_age=86400):  # 24 hours default
        """Verify and decode a password reset token"""
        try:
            data = self.serializer.loads(token, max_age=max_age)
            if data.get('action') != 'password_reset':
                return None
            return data
        except Exception as e:
            current_app.logger.error(f"Token verification failed: {e}")
            return None

    def send_student_credentials(self, student_name, student_email, student_id, temp_password=None):
        """Send email with password setup link only (no login credentials)"""
        try:
            # Generate token for password reset
            token = self.generate_password_reset_token(student_id)
            
            # Create password setup URL
            password_setup_url = url_for('misc_routes.reset_password', token=token, _external=True)
            
            # Default HTML email content for modern email clients 
            html_content = f"""
            <html>
            <body style="font-family: Arial, sans-serif; line-height: 1.6;">
                <h2>Welcome to CCA Portal, {student_name}!</h2>
                
                <p>Your student account has been created by an administrator.</p>
                
                <div style="background-color: #fff3cd; padding: 15px; margin: 20px 0; border-radius: 5px; border-left: 4px solid #ffc107;">
                    <h4>🔒 Account Setup Required</h4>
                    <p><strong>You must set your password before you can access the CCA Portal.</strong></p>
                </div>
                
                <div style="background-color: #f0f0f0; padding: 15px; margin: 20px 0; border-radius: 5px;">
                    <h3>Your Account Details:</h3>
                    <p><strong>Student ID:</strong> {student_id}</p>
                    <p><strong>Email:</strong> {student_email}</p>
                </div>
                
                <h3>Next Steps:</h3>
                <ol>
                    <li>Click the button below to set your password</li>
                    <li>Create a secure password of your choice</li>
                    <li>Login to CCA Portal with your Student ID and new password</li>
                </ol>
                
                <div style="text-align: center; margin: 30px 0;">
                    <a href="{password_setup_url}" style="background-color: #007bff; color: white; padding: 15px 30px; text-decoration: none; border-radius: 5px; font-size: 16px; display: inline-block;">
                        Set My Password
                    </a>
                </div>
                
                <div style="background-color: #e9ecef; padding: 15px; margin: 20px 0; border-radius: 5px;">
                    <h4>Important Security Information:</h4>
                    <ul>
                        <li>This setup link expires in 24 hours for security</li>
                        <li>You cannot login until you set your password</li>
                        <li>Choose a strong, unique password</li>
                        <li>Keep your login credentials secure</li>
                    </ul>
                </div>
                
                <hr>
                <p><small>This is an automated message from CCA Portal. If you have questions, contact your administrator.</small></p>
                <p><small>If you did not expect this email, please contact IT support immediately.</small></p>
            </body>
            </html>
            """
            
            # Simplified plaintext as fallback for older email clients
            text_content = f"""
    Welcome to CCA Portal, {student_name}!

    Your student account has been created.

    Account Details:
    Student ID: {student_id}
    Email: {student_email}

    IMPORTANT: You must set your password before you can access the portal.

    To set your password, visit this link:
    {password_setup_url}

    Steps to get started:
    1. Click the link above to set your password
    2. Create a secure password of your choice  
    3. Login to CCA Portal using your Student ID and new password

    This setup link expires in 24 hours for security.

    If you have questions, contact your administrator.

    ---
    This is an automated message from CCA Portal.
            """
            
            # Create and send message
            msg = Message(
                subject="CCA Portal Account Setup - Set Your Password",
                recipients=[student_email],
                html=html_content,
                body=text_content
            )
            
            self.mail.send(msg)
            current_app.logger.info(f"Password setup email sent to {student_email}")
            return True
            
        except Exception as e:
            current_app.logger.error(f"Failed to send email to {student_email}: {e}")
            return False
        
email_service = EmailService()