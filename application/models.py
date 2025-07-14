from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
db = SQLAlchemy()

class User(db.Model):
    __tablename__ = 'UserDetails'
    UserId = db.Column(db.Integer, primary_key=True)
    Username = db.Column(db.String(255), unique=True, nullable=False)
    Password = db.Column(db.String(255), nullable=False)
    SystemRole = db.Column(db.String(50), nullable=False)
    StudentId = db.Column(db.Integer, db.ForeignKey('Student.StudentId'))
    MFATOTPSecret = db.Column(db.String(255))
    FailedLoginAttempts = db.Column(db.Integer, default=0)
    IsLocked = db.Column(db.Boolean, default=False)
    LastFailedLogin = db.Column(db.DateTime)
    PasswordLastSet = db.Column(db.DateTime, default=datetime.utcnow)

    student = db.relationship('Student', backref='user', uselist=False)

class Student(db.Model):
    __tablename__ = 'Student'
    StudentId = db.Column(db.Integer, primary_key=True)
    Name = db.Column(db.String(255), nullable=False)
    Email = db.Column(db.String(255), unique=True, nullable=False)

    user_details = db.relationship('User', backref='student_details', uselist=False)

class CCAMembers(db.Model):
    __tablename__ = 'CCAMembers'
    MemberId = db.Column(db.Integer, primary_key=True)
    UserId = db.Column(db.Integer, db.ForeignKey('UserDetails.UserId'))
    CCAId = db.Column(db.Integer, db.ForeignKey('CCA.CCAId'))
    CCARole = db.Column(db.String(50), nullable=False)

    user = db.relationship('User', backref='cca_memberships')
    cca = db.relationship('CCA', backref='members')

class CCA(db.Model):
    __tablename__ = 'CCA'
    CCAId = db.Column(db.Integer, primary_key=True)
    Name = db.Column(db.String(255), nullable=False)
    Description = db.Column(db.Text)

class Poll(db.Model):
    __tablename__ = 'Poll'
    PollId = db.Column(db.Integer, primary_key=True)
    CCAId = db.Column(db.Integer, db.ForeignKey('CCA.CCAId'))
    Question = db.Column(db.String(255), nullable=False)
    QuestionType = db.Column(db.String(20))
    StartDate = db.Column(db.DateTime, nullable=False)
    EndDate = db.Column(db.DateTime, nullable=False)
    IsAnonymous = db.Column(db.Boolean, nullable=False)
    IsActive = db.Column(db.Boolean, nullable=False)

    cca = db.relationship('CCA', backref='polls')
    options = db.relationship('PollOption', backref='poll', cascade='all, delete-orphan')

class PollOption(db.Model):
    __tablename__ = 'Options'
    OptionId = db.Column(db.Integer, primary_key=True)
    PollId = db.Column(db.Integer, db.ForeignKey('Poll.PollId'))
    OptionText = db.Column(db.String(255), nullable=False)

    votes = db.relationship('PollVote', backref='option', cascade='all, delete-orphan')

class PollVote(db.Model):
    __tablename__ = 'Votes'
    VoteId = db.Column(db.Integer, primary_key=True)
    PollId = db.Column(db.Integer, db.ForeignKey('Poll.PollId'))
    UserId = db.Column(db.Integer, db.ForeignKey('UserDetails.UserId'))
    OptionId = db.Column(db.Integer, db.ForeignKey('Options.OptionId'))
    VotedTime = db.Column(db.DateTime, nullable=False)
    user = db.relationship('User', backref='votes')

class VoteToken(db.Model):
    __tablename__ = 'VoteTokens'
    Token = db.Column(db.String(255), unique=True, nullable=False, primary_key=True)
    UserId = db.Column(db.Integer, db.ForeignKey('UserDetails.UserId'))
    PollId = db.Column(db.Integer, db.ForeignKey('Poll.PollId'))
    IsUsed = db.Column(db.Boolean, default=False)
    IssuedTime = db.Column(db.DateTime, nullable=False)
    ExpiryTime = db.Column(db.DateTime, nullable=False)

    user = db.relationship('User', backref='vote_tokens')
    poll = db.relationship('Poll', backref='vote_tokens')

class LoginLog(db.Model):
    __tablename__ = 'LoginLog'
    LogId = db.Column(db.Integer, primary_key=True)
    Username = db.Column(db.String(255))
    UserId = db.Column(db.Integer, db.ForeignKey('UserDetails.UserId'), nullable=True)
    IPAddress = db.Column(db.String(45))
    Timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    Success = db.Column(db.Boolean, nullable=False)
    Reason = db.Column(db.String(255))

class AdminLog(db.Model):
    __tablename__ = 'AdminLog'
    LogId = db.Column(db.Integer, primary_key=True)
    AdminUserId = db.Column(db.Integer, db.ForeignKey('UserDetails.UserId'))
    Action = db.Column(db.String(255), nullable=False)
    Timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    IPAddress = db.Column(db.String(45))