from flask import render_template, request, redirect, url_for, session, flash, Blueprint
import pyotp, qrcode
from io import BytesIO
from base64 import b64encode
import pyodbc
from datetime import datetime, timedelta, timezone
import secrets
import hashlib
import bcrypt
import os
from application.misc_routes import validate_password_nist
from application.auth_utils import login_required_with_mfa
from application.models import db, User, CCAMembers, Poll, PollOption, PollVote, VoteToken, Student, CCA
from sqlalchemy import func, and_, or_, case, literal_column

def convert_utc_to_gmt8_display(utc_datetime):
    """Convert UTC datetime to GMT+8 for display purposes"""
    if utc_datetime and isinstance(utc_datetime, datetime):
        # Add 8 hours to convert UTC to GMT+8
        gmt8_datetime = utc_datetime + timedelta(hours=8)
        return gmt8_datetime.strftime('%Y-%m-%d %H:%M')
    return str(utc_datetime) if utc_datetime else 'N/A'

# Create a Blueprint
student_bp = Blueprint('student_routes', __name__)

# registration function for student routes
def register_student_routes(app, get_db_connection, login_required):
    
    @student_bp.route("/mfa-setup", methods=["GET", "POST"])
    @login_required
    def mfa_setup():
        conn = get_db_connection()
        if not conn:
            flash("Database connection error.", "error")
            return redirect(url_for("student_routes.dashboard"))

        try:
            # Get user with current session's user ID
            user = User.query.filter_by(UserId=session["user_id"]).first()

            if user and user.MFATOTPSecret:
                return redirect(url_for("misc_routes.mfa_verify"))

            # Always ensure we have a temp secret in session
            if "mfa_temp_secret" not in session:
                session["mfa_temp_secret"] = pyotp.random_base32()

            secret = session["mfa_temp_secret"]
            totp   = pyotp.TOTP(secret)
            uri    = totp.provisioning_uri(
                        name=session["email"],
                        issuer_name="CCAP Web Portal"
                    )

            # Build QR code (base64 once per request)
            qr_buf = BytesIO()
            qrcode.make(uri).save(qr_buf, format="PNG")
            qr_b64 = b64encode(qr_buf.getvalue()).decode()

            # ---------- POST: user submits first code ----------
            if request.method == "POST":
                code = request.form.get("mfa_code", "").strip()
                if totp.verify(code):
                    user.MFATOTPSecret = secret
                    db.session.commit()
                    # Updates the user's MFA secret and commits the change to the database.
                    session.pop("mfa_temp_secret", None)
                    session["mfa_authenticated"] = True
                    flash("MFA setup complete.", "success")
                    return redirect(url_for("student_routes.dashboard"))
                else:
                    flash("Invalid code, try again.", "error")

            # ---------- GET or invalid code: show page ----------
            return render_template("mfa_setup.html", qr_b64=qr_b64, secret=secret)

        finally:
            conn.close()

    @student_bp.route('/dashboard')
    @login_required_with_mfa
    def dashboard():
        if os.getenv("TESTING") == "1":
            session['mfa_authenticated'] = True
        elif not session.get("mfa_authenticated"):
            return redirect(url_for("misc_routes.mfa_verify"))
    
        if session.get('role') == 'admin':
            return redirect(url_for('admin_routes.admin_dashboard'))
        
        try:
            # Get user and calculate password expiry warning
            user = User.query.filter_by(UserId=session['user_id']).first()
            days_left = None
            if user and user.PasswordLastSet:
                # Make sure both datetimes are timezone-aware for comparison
                password_last_set = user.PasswordLastSet
                if password_last_set.tzinfo is None:
                    # If database datetime is naive, assume it's UTC
                    password_last_set = password_last_set.replace(tzinfo=timezone.utc)
                
                days_since = (datetime.now(timezone.utc) - password_last_set).days
                days_left = 365 - days_since

            # Get CCAs the user is a member of
            user_ccas = db.session.query(CCA.CCAId, CCA.Name, CCA.Description, CCAMembers.CCARole).join(CCAMembers, CCA.CCAId == CCAMembers.CCAId).filter(CCAMembers.UserId == session['user_id']).all()
            
            ccas = []
            user_is_moderator = False
            for cca_row in user_ccas:
                ccas.append({
                    'id': cca_row[0],
                    'name': cca_row[1],
                    'description': cca_row[2],
                    'role': cca_row[3]
                })
                if cca_row[3] == 'moderator':
                    user_is_moderator = True
            
            if ccas:
                cca_ids = [c['id'] for c in ccas]

                # Get active polls in user's CCAs
                poll_results = db.session.query(
                    Poll.PollId,
                    Poll.Question,
                    Poll.EndDate,
                    CCA.Name.label('CCAName'),
                    func.datediff(literal_column('day'), func.now(), Poll.EndDate).label('DaysRemaining')
                ).join(CCA, Poll.CCAId == CCA.CCAId).filter(Poll.CCAId.in_(cca_ids), Poll.IsActive == True).order_by(Poll.EndDate.asc()).all()
                
                available_polls = []
                for poll_row in poll_results:
                    available_polls.append({
                        'id': poll_row[0],
                        'title': poll_row[1],
                        'end_date': convert_utc_to_gmt8_display(poll_row[2]).split(' ')[0] if poll_row[2] else '',  # Just date part
                        'cca': poll_row[3],
                        'days_remaining': poll_row[4] if poll_row[4] is not None else 0
                    })
            else:
                available_polls = []
            
            return render_template(
                'dashboard.html',
                ccas=ccas,
                available_polls=available_polls,
                user_name=session['name'],
                user_role=session['role'],
                user_is_moderator=user_is_moderator,
                password_days_left=days_left
            )
            
        except Exception as e:
            print(f"Dashboard data error: {e}")
            flash('Error loading dashboard data.', 'error')
            return render_template(
                'dashboard.html',
                ccas=[],
                available_polls=[],
                user_name=session['name'],
                user_role=session['role'],
                user_is_moderator=False,
                password_days_left=None
            )

    @student_bp.route('/my-ccas')
    @login_required_with_mfa
    def my_ccas():
        if session.get('role') == 'admin':
            return redirect(url_for('admin_routes.admin_dashboard'))
        
        try:
            # Get CCAs the user is a member of
            user_ccas_rows = db.session.query(CCA.CCAId, CCA.Name, CCA.Description, CCAMembers.CCARole).join(CCAMembers, CCA.CCAId == CCAMembers.CCAId).filter(CCAMembers.UserId == session['user_id']).order_by(CCA.Name).all()
            
            ccas_list = []
            moderator_ccas_list = []
            user_is_moderator = False
            
            for cca_row in user_ccas_rows:
                cca_data = {
                    'id': cca_row[0],
                    'name': cca_row[1],
                    'description': cca_row[2],
                    'role': cca_row[3]
                }
                ccas_list.append(cca_data)
                if cca_row[3] == 'moderator':
                    moderator_ccas_list.append(cca_data)
                    user_is_moderator = True
            
            return render_template('my_ccas.html', 
                                ccas=ccas_list, 
                                moderator_ccas=moderator_ccas_list,
                                user_is_moderator=user_is_moderator,
                                user_name=session['name'],
                                user_role=session['role'])
            
        except Exception as e:
            print(f"My CCAs error: {e}")
            flash('Error loading CCAs.', 'error')
            return redirect(url_for('student_routes.dashboard'))

    @student_bp.route('/polls')
    @login_required_with_mfa
    def view_polls():
        if session.get('role') == 'admin':
            return redirect(url_for('admin_routes.admin_dashboard'))

        try:
            # Check if user is a moderator in CCA
            user_is_moderator = db.session.query(CCAMembers).filter_by(UserId=session['user_id'], CCARole='moderator').count() > 0
            # Get IDs of all CCAs the user is a member of
            user_cca_ids = [cca.CCAId for cca in db.session.query(CCA.CCAId).join(CCAMembers).filter(CCAMembers.UserId == session['user_id']).distinct().all()]

            polls_data_rows = []
            if user_cca_ids:
                # Query for polls in user's CCAs
                polls_data_rows = db.session.query(
                    Poll.PollId, Poll.CCAId, Poll.Question, Poll.QuestionType,
                    Poll.StartDate, Poll.EndDate, Poll.IsAnonymous,
                    Poll.IsActive.label('LiveIsActive'), CCA.Name.label('CCAName')
                ).join(CCA).filter(Poll.CCAId.in_(user_cca_ids)).order_by(Poll.EndDate.desc(), Poll.StartDate.desc()).all()

            processed_polls = []
            for row in polls_data_rows:
                processed_polls.append({
                    'PollId': row[0], 
                    'CCAId': row[1], 
                    'Question': row[2], 
                    'QuestionType': row[3],
                    'StartDate': convert_utc_to_gmt8_display(row[4]),
                    'EndDate': convert_utc_to_gmt8_display(row[5]),
                    'IsAnonymous': row[6], 
                    'LiveIsActive': row[7],
                    'CCAName': row[8]
                })

            if not user_cca_ids or not polls_data_rows:
                processed_polls = []

            return render_template('view_poll.html', 
                                polls=processed_polls, 
                                user_is_moderator=user_is_moderator,
                                user_name=session.get('name'))

        except Exception as e:
            print(f"Error fetching polls: {e}")
            flash('Error fetching polls.', 'error')
            return redirect(url_for('student_routes.dashboard'))

    @student_bp.route('/poll/<int:poll_id>')
    @login_required_with_mfa
    def view_poll_detail(poll_id):
        try:
            # Check if user is moderator
            user_is_moderator = db.session.query(CCAMembers).filter_by(UserId=session['user_id'], CCARole='moderator').count() > 0

            # Get poll details
            poll_data_row = db.session.query(
                Poll.PollId, Poll.Question, Poll.QuestionType, Poll.StartDate, Poll.EndDate,
                Poll.IsAnonymous, CCA.Name.label('CCAName'), Poll.IsActive.label('LiveIsActive')
            ).join(CCA, Poll.CCAId == CCA.CCAId).filter(Poll.PollId == poll_id).first()

            if not poll_data_row:
                flash('Access denied.', 'error')
                return redirect(url_for('student_routes.view_polls'))

            # Check if user is a member of the CCA for this poll
            is_member_of_cca = db.session.query(CCAMembers).join(Poll, CCAMembers.CCAId == Poll.CCAId).filter(CCAMembers.UserId == session['user_id'], Poll.PollId == poll_id).count() > 0

            if not is_member_of_cca and session['role'] != 'admin':
                flash('Access denied.', 'error')
                return redirect(url_for('student_routes.view_polls'))

            start_date_obj = poll_data_row[3]
            end_date_obj = poll_data_row[4]
            start_date_str = start_date_obj.strftime('%Y-%m-%d %H:%M') if isinstance(start_date_obj, datetime) else str(start_date_obj) if start_date_obj else 'N/A'
            end_date_str = end_date_obj.strftime('%Y-%m-%d %H:%M') if isinstance(end_date_obj, datetime) else str(end_date_obj) if end_date_obj else 'N/A'
            
            # Calculate if poll has ended, handling timezone-aware vs timezone-naive comparison
            is_ended_status = False
            if isinstance(end_date_obj, datetime):
                # Make sure both datetimes are timezone-aware for comparison
                if end_date_obj.tzinfo is None:
                    # If database datetime is naive, assume it's UTC
                    end_date_obj = end_date_obj.replace(tzinfo=timezone.utc)
                is_ended_status = datetime.now(timezone.utc) > end_date_obj
            
            poll = {
                'PollId': poll_data_row[0], 
                'Question': poll_data_row[1], 
                'QuestionType': poll_data_row[2],
                'StartDate': convert_utc_to_gmt8_display(poll_data_row[3]),
                'EndDate': convert_utc_to_gmt8_display(poll_data_row[4]),
                'IsAnonymous': poll_data_row[5],
                'Description': None, 
                'CCAName': poll_data_row[6], 
                'LiveIsActive': poll_data_row[7],
                'is_ended': is_ended_status
            }
            options_data = db.session.query(
                PollOption.OptionId, PollOption.OptionText, func.count(PollVote.VoteId).label('VoteCount')
            ).outerjoin(PollVote, PollOption.OptionId == PollVote.OptionId).filter(PollOption.PollId == poll_id).group_by(PollOption.OptionId, PollOption.OptionText).order_by(PollOption.OptionId).all()
            
            # Gets poll options and vote counts.
            options = [{'OptionId': opt[0], 'OptionText': opt[1], 'VoteCount': opt[2]} for opt in options_data]

            # Check if user has voted
            has_voted = False
            if poll['IsAnonymous']:
                # For anonymous polls, check if the user's token has been used
                token_status = db.session.query(VoteToken.IsUsed).filter_by(PollId=poll_id, UserId=session['user_id']).first()
                # Checks if the user's vote token has been used.
                if token_status and token_status[0]:
                    has_voted = True
            else:
                # For non-anonymous polls, check the Votes table directly
                if db.session.query(PollVote).filter(and_(PollVote.PollId == poll_id, PollVote.UserId == session['user_id'])).count() > 0:
                    has_voted = True
            
            user_votes = []
            if has_voted and poll['QuestionType'] == 'multiple':
                user_votes_data = db.session.query(PollVote.OptionId).filter_by(PollId=poll_id, UserId=session['user_id']).all()
                # Get the user's votes for a multiple choice poll.
                user_votes = [uv[0] for uv in user_votes_data]

            vote_token = None
            if poll['IsAnonymous'] and poll['LiveIsActive']:
                # Check if token already exists and if it is unused
                token_status_row = db.session.query(VoteToken.IsUsed).filter_by(PollId=poll_id, UserId=session['user_id']).first()

                if token_status_row:
                    is_used = token_status_row[0]
                    if not is_used:
                        # Token exists but unused → safely delete and reissue
                        db.session.query(VoteToken).filter_by(PollId=poll_id, UserId=session['user_id']).delete()
                        db.session.commit()

                        # Reissue a new token
                        raw_token = secrets.token_hex(32)
                        hashed_token = hashlib.sha256(raw_token.encode()).hexdigest()
                        new_token = VoteToken(Token=hashed_token, PollId=poll_id, UserId=session['user_id'], IssuedTime=datetime.now(timezone.utc), ExpiryTime=datetime.now(timezone.utc) + timedelta(minutes=10))
                        db.session.add(new_token)
                        db.session.commit()

                        # Inserts a new vote token for the user.
                        vote_token = raw_token
                    else:
                        vote_token = None  # Already used, no reissue
                else:
                    # No token exists yet → issue first time
                    raw_token = secrets.token_hex(32)
                    hashed_token = hashlib.sha256(raw_token.encode()).hexdigest()
                    new_token = VoteToken(Token=hashed_token, PollId=poll_id, UserId=session['user_id'], IssuedTime=datetime.now(timezone.utc), ExpiryTime=datetime.now(timezone.utc) + timedelta(minutes=10))
                    db.session.add(new_token)
                    db.session.commit()

                    # Inserts a new vote token for the user.
                    vote_token = raw_token

            return render_template('poll_detail.html', 
                                poll=poll, 
                                options=options, 
                                has_voted=has_voted, 
                                user_votes=user_votes, 
                                user_name=session.get('name'),
                                user_is_moderator=user_is_moderator, vote_token=vote_token)
        
        except Exception as e:
            print(f"Error fetching poll details for poll {poll_id}: {e}")
            flash('Error fetching poll details.', 'error')
            return redirect(url_for('student_routes.view_polls'))

    @student_bp.route('/poll/<int:poll_id>/vote', methods=['POST'])
    @login_required_with_mfa
    def submit_vote(poll_id):
        if session.get('role') == 'admin':
            flash('Admins are not allowed to vote.', 'error')
            return redirect(url_for('student_routes.view_poll_detail', poll_id=poll_id))

        try:
            # Get poll information to validate the vote
            poll_info = db.session.query(Poll.IsActive, Poll.CCAId, Poll.QuestionType).filter_by(PollId=poll_id).first()

            if not poll_info:
                flash('Access denied.', 'error')
                return redirect(url_for('student_routes.view_polls'))

            live_is_active, cca_id, question_type = poll_info

            if not live_is_active:
                flash('This poll is closed for voting.', 'error')
                return redirect(url_for('student_routes.view_poll_detail', poll_id=poll_id))

            # Check if user is a member of the CCA
            is_member_of_cca = db.session.query(CCAMembers).filter_by(UserId=session['user_id'], CCAId=cca_id).count() > 0

            if not is_member_of_cca:
                flash('Access denied.', 'error')
                return redirect(url_for('student_routes.view_poll_detail', poll_id=poll_id))

            # Check if user has already voted
            has_voted = db.session.query(PollVote).filter_by(PollId=poll_id, UserId=session['user_id']).count() > 0
            # Check if poll is anonymous
            is_anonymous = db.session.query(Poll.IsAnonymous).filter_by(PollId=poll_id).scalar()

            selected_option_ids = []
            if question_type == 'single_choice':
                option_id = request.form.get('option_id')
                if option_id:
                    selected_option_ids.append(option_id)
            elif question_type == 'multiple_choice':
                selected_option_ids = request.form.getlist('option_ids[]')
            else:
                flash('Invalid poll type.', 'error')
                return redirect(url_for('student_routes.view_poll_detail', poll_id=poll_id))

            # Get valid option IDs for the poll
            valid_option_ids_tuples = db.session.query(PollOption.OptionId).filter_by(PollId=poll_id).all()
            valid_option_ids = [str(opt_id[0]) for opt_id in valid_option_ids_tuples]

            for opt_id in selected_option_ids:
                if opt_id not in valid_option_ids:
                    flash(f'Invalid option selected: {opt_id}', 'error')
                    return redirect(url_for('student_routes.view_poll_detail', poll_id=poll_id))

            # Token validation only if not already voted
            if is_anonymous and not has_voted:
                raw_token = request.form.get('vote_token')
                if not raw_token:
                    flash('Missing vote token for anonymous poll.', 'error')
                    return redirect(url_for('student_routes.view_poll_detail', poll_id=poll_id))

                # Get vote token for validation
                hashed_token = hashlib.sha256(raw_token.encode()).hexdigest()
                token_row = db.session.query(VoteToken).filter_by(Token=hashed_token, PollId=poll_id, UserId=session['user_id']).first()

                if not token_row:
                    flash('Invalid or expired vote token.', 'error')
                    return redirect(url_for('student_routes.view_poll_detail', poll_id=poll_id))

                is_used, expiry_time = token_row.IsUsed, token_row.ExpiryTime
                if is_used:
                    flash('This vote token has already been used.', 'error')
                    return redirect(url_for('student_routes.view_poll_detail', poll_id=poll_id))
                if expiry_time:
                    # Make sure both datetimes are timezone-aware for comparison
                    if expiry_time.tzinfo is None:
                        # If database datetime is naive, assume it's UTC
                        expiry_time = expiry_time.replace(tzinfo=timezone.utc)
                    
                    if datetime.now(timezone.utc) > expiry_time:
                        flash('Your vote token has expired. Please refresh and try again.', 'error')
                        return redirect(url_for('student_routes.view_poll_detail', poll_id=poll_id))
                
                token_row.IsUsed = True

            # Insert vote only if not already voted
            if not has_voted:
                for option_id in selected_option_ids:
                    new_vote = PollVote(PollId=poll_id, OptionId=option_id, UserId=session['user_id'], VotedTime=datetime.now(timezone.utc))
                    db.session.add(new_vote)
                db.session.commit()
                flash('Your vote has been submitted successfully.', 'success')
            else:
                flash('You have already voted in this poll.', 'info')

        except Exception as e:
            db.session.rollback()
            print(f"Error submitting vote for poll {poll_id}: {e}")
            flash('An error occurred while submitting your vote. Please try again.', 'error')

        return redirect(url_for('student_routes.view_poll_detail', poll_id=poll_id))

    @student_bp.route('/poll/<int:poll_id>/results')
    @login_required_with_mfa
    def view_poll_results(poll_id):
        try:
            # Checks if the user is a moderator for the poll's CCA
            user_is_moderator = db.session.query(CCAMembers).join(Poll, CCAMembers.CCAId == Poll.CCAId).filter(
                CCAMembers.UserId == session['user_id'],
                Poll.PollId == poll_id,
                CCAMembers.CCARole == 'moderator'
            ).count() > 0

            # Check if the poll is anonymous
            is_anonymous = db.session.query(Poll.IsAnonymous).filter_by(PollId=poll_id).scalar()

            if is_anonymous and not user_is_moderator and session['role'] != 'admin':
                flash('You cannot view the results of an anonymous poll.', 'error')
                return redirect(url_for('student_routes.view_poll_detail', poll_id=poll_id)) 

            # Get basic poll information for results page           
            poll_info = db.session.query(
                Poll.PollId, Poll.Question, Poll.IsAnonymous, Poll.StartDate, Poll.EndDate, 
                Poll.QuestionType, CCA.Name.label('CCAName')
            ).join(CCA, Poll.CCAId == CCA.CCAId).filter(Poll.PollId == poll_id).first()

            if not poll_info:
                flash('Poll not found.', 'error')
                return redirect(url_for('student_routes.view_polls'))

            poll = {
                'PollId': poll_info[0], 
                'Question': poll_info[1], 
                'IsAnonymous': poll_info[2], 
                'StartDate': convert_utc_to_gmt8_display(poll_info[3]),
                'EndDate': convert_utc_to_gmt8_display(poll_info[4]),
                'QuestionType': poll_info[5],
                'CCAName': poll_info[6]
            }
            
            # Get poll options with vote counts
            options_data = db.session.query(
                PollOption.OptionId, PollOption.OptionText, func.count(PollVote.VoteId).label('VoteCount')
            ).outerjoin(PollVote, PollOption.OptionId == PollVote.OptionId).filter(PollOption.PollId == poll_id).group_by(PollOption.OptionId, PollOption.OptionText).order_by(func.count(PollVote.VoteId).desc()).all()
            
            # Calculate total votes
            total_votes = sum(opt[2] for opt in options_data)
            
            # Process options with percentages
            options = []
            for opt in options_data:
                percentage = round((opt[2] / total_votes * 100), 1) if total_votes > 0 else 0
                options.append({
                    'OptionId': opt[0],
                    'OptionText': opt[1],
                    'VoteCount': opt[2],
                    'Percentage': percentage
                })
            
            # Get total eligible voters (CCA members)
            poll_cca_id = db.session.query(Poll.CCAId).filter_by(PollId=poll_id).scalar()
            total_eligible_voters = db.session.query(CCAMembers).filter_by(CCAId=poll_cca_id).count()
            
            # Calculate participation rate
            participation_rate = round((total_votes / total_eligible_voters * 100), 1) if total_eligible_voters > 0 else 0
            
            # Check if current user voted and get their votes
            user_voted = db.session.query(PollVote).filter_by(PollId=poll_id, UserId=session['user_id']).count() > 0
            user_votes = []
            if user_voted:
                user_votes_data = db.session.query(PollVote.OptionId).filter_by(PollId=poll_id, UserId=session['user_id']).all()
                user_votes = [uv[0] for uv in user_votes_data]
            
            # Get results for a non-anonymous poll with student name and email
            results_data = db.session.query(
                PollOption.OptionText, Student.Name.label('VoterName'), Student.Email.label('VoterEmail')
            ).join(PollVote, PollOption.OptionId == PollVote.OptionId).join(User, PollVote.UserId == User.UserId).join(Student, User.StudentId == Student.StudentId).filter(PollVote.PollId == poll_id).order_by(PollOption.OptionText, Student.Name).all()

            results = {}
            for row in results_data:
                option_text, voter_name, voter_email = row
                if option_text not in results:
                    results[option_text] = []
                results[option_text].append({'name': voter_name, 'email': voter_email})

            return render_template('view_result.html', 
                                 poll=poll, 
                                 results=results, 
                                 options=options,
                                 total_votes=total_votes,
                                 total_eligible_voters=total_eligible_voters,
                                 participation_rate=participation_rate,
                                 user_voted=user_voted,
                                 user_votes=user_votes,
                                 user_name=session.get('name'))

        except Exception as e:
            print(f"Error fetching poll results for poll {poll_id}: {e}")
            flash('Error fetching poll results.', 'error')
            return redirect(url_for('student_routes.view_poll_detail', poll_id=poll_id))

    @student_bp.route('/cca/<int:cca_id>')
    @login_required_with_mfa
    def student_view_cca(cca_id):
        if session.get('role') == 'admin':
            return redirect(url_for('admin_routes.admin_dashboard'))
        
        """View-only CCA page for normal students (non-moderators)"""
        
        try:
            # Check if user is moderator
            user_is_moderator = db.session.query(CCAMembers).filter_by(UserId=session['user_id'], CCARole='moderator').count() > 0

            # Check user's role in CCA
            membership = db.session.query(CCAMembers.CCARole).filter_by(UserId=session['user_id'], CCAId=cca_id).first()
            
            if not membership:
                flash('Access denied.', 'error')
                return redirect(url_for('student_routes.my_ccas'))
            
            # Get CCA details by ID
            cca = db.session.query(CCA.CCAId, CCA.Name, CCA.Description).filter_by(CCAId=cca_id).first()
            
            if not cca:
                flash('Access denied.', 'error')
                return redirect(url_for('student_routes.my_ccas'))
            
            # Get all members of the CCA ordered by role and name
            members = db.session.query(
                Student.StudentId, Student.Name, Student.Email, CCAMembers.CCARole, CCAMembers.MemberId
            ).join(User, Student.StudentId == User.StudentId).join(CCAMembers, User.UserId == CCAMembers.UserId).filter(CCAMembers.CCAId == cca_id).order_by(CCAMembers.CCARole.desc(), Student.Name).all()
            
            return render_template('student_view_cca.html', 
                                cca=cca, 
                                members=members,
                                user_name=session['name'],
                                user_is_moderator=user_is_moderator)
            
        except Exception as e:
            print(f"Error fetching cca details for cca {cca_id}: {e}")
            flash('Error fetching cca details.', 'error')
            return redirect(url_for('student_routes.my_ccas'))

    @student_bp.route('/change-password', methods=['GET', 'POST'])
    @login_required_with_mfa
    def change_password():
        # Helper function to check if user is moderator
        def get_moderator_status():
            return db.session.query(CCAMembers).filter_by(UserId=session['user_id'], CCARole='moderator').count() > 0

        if request.method == 'POST':
            current_password = request.form.get('current_password', '').strip()
            new_password = request.form.get('new_password', '').strip()
            confirm_password = request.form.get('confirm_password', '').strip()
            
            # Get moderator status for all error returns
            user_is_moderator = get_moderator_status()
            
            # Basic validation
            if not all([current_password, new_password, confirm_password]):
                flash('All fields are required.', 'error')
                return render_template('change_password.html', 
                                    user_name=session['name'],
                                    user_is_moderator=user_is_moderator)
            
            if new_password != confirm_password:
                flash('New passwords do not match.', 'error')
                return render_template('change_password.html',
                                    user_name=session['name'],
                                    user_is_moderator=user_is_moderator)
            
            is_valid, errors = validate_password_nist(new_password)
            if not is_valid:
                for error in errors:
                    flash(error, 'error')
                return render_template('change_password.html',
                                    user_name=session['name'],
                                    user_is_moderator=user_is_moderator)
            
            try:
                # Get user object for password verification
                user = db.session.query(User).filter_by(UserId=session['user_id']).first()
                
                if not user:
                    flash('User not found.', 'error')
                    return redirect(url_for('auth_routes.login'))
                
                stored_password = user.Password
                
                # Verify current password
                if bcrypt.checkpw(current_password.encode('utf-8'), stored_password.encode('utf-8')):
                    # Hash new password
                    hashed_new_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
                    
                    user.Password = hashed_new_password.decode('utf-8')
                    user.PasswordLastSet = datetime.now(timezone.utc)

                    db.session.commit()
                    
                    flash('Password changed successfully.', 'success')
                    return redirect(url_for('student_routes.dashboard'))
                else:
                    flash('Incorrect current password.', 'error')
                    return render_template('change_password.html',
                                        user_name=session['name'],
                                        user_is_moderator=user_is_moderator)
                
            except Exception as e:
                db.session.rollback()
                print(f"Error changing password: {e}")
                flash('An error occurred while changing your password.', 'error')
                return render_template('change_password.html',
                                    user_name=session['name'],
                                    user_is_moderator=user_is_moderator)

        
        # GET request - check if user is moderator and pass to template
        user_is_moderator = get_moderator_status()
        return render_template('change_password.html', 
                            user_name=session['name'],
                            user_is_moderator=user_is_moderator)

    app.register_blueprint(student_bp)