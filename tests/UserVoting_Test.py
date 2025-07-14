from app import app
from application.models import db, User, Student, CCA, CCAMembers, Poll, PollVote, PollOption
import bcrypt
from sqlalchemy import text
from datetime import datetime
import hashlib
import os

#--------------------- TESTING USER VOTING ----------------------------#
def test_authenticated_user_vote():
    poll_id = 9
    student_id = 2305106
    username = "2305106"
    password = "ffffff"

    with app.app_context():
        # Ensure student exists
        student = Student.query.get(student_id)
        if not student:
            student = Student(
                StudentId=student_id,
                Name="Test Voter",
                Email="voter@example.com",
                DOB="2000-01-01",
                ContactNumber="81234567"
            )
            db.session.add(student)
            db.session.commit()

        # Ensure user exists
        user = User.query.filter_by(Username=username).first()
        if not user:
            user = User(
                StudentId=student_id,
                Username=username,
                Password=bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode(),
                SystemRole="student",
                PasswordLastSet=datetime.utcnow()
            )
            db.session.add(user)
            db.session.commit()
        user_id = user.UserId

        # Ensure CCA exists
        cca = CCA.query.get(7)
        if not cca:
            cca = CCA(CCAId=7, Name="Test CCA", Description="For Poll")
            db.session.add(cca)
            db.session.commit()

        # Ensure user is a member of the CCA
        if not CCAMembers.query.filter_by(UserId=user_id, CCAId=cca.CCAId).first():
            db.session.add(CCAMembers(UserId=user_id, CCAId=cca.CCAId, CCARole="member"))
            db.session.commit()

        # Ensure poll option exists
        option = PollOption.query.filter_by(PollId=poll_id).first()
        assert option is not None, f"No option found for poll {poll_id}"
        option_id = option.OptionId

        # Delete any existing vote
        PollVote.query.filter_by(UserId=user_id, PollId=poll_id).delete()
        db.session.commit()

    # Simulate login and vote
    with app.test_client() as client:
        login_response = client.post("/login", data={"username": username, "password": password}, follow_redirects=True)
        
        # Check for login failure clues
        if not os.getenv("TESTING") == "1":
            assert b"captcha" not in login_response.data.lower(), "Login blocked by CAPTCHA"
        assert b"invalid" not in login_response.data.lower(), "Login failed due to invalid credentials"

        # Force session variables
        with client.session_transaction() as sess:
            sess["user_id"] = user_id
            sess["role"] = "student"
            sess["mfa_authenticated"] = True

        print("Inserting vote for:", user_id, poll_id, option_id)

        # Vote submission
        vote_response = client.post(f"/poll/{poll_id}/vote", data={"option": str(option_id)}, follow_redirects=True)
        print("▶ VOTE RESPONSE:", vote_response.data.decode()[:1000])  # debug