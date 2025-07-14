from flask import render_template, request, redirect, url_for, session, flash, Blueprint
from email_service import email_service
import bcrypt
from datetime import datetime, timezone
from application.auth_utils import admin_required
from .models import db, CCA, Student, CCAMembers, User, Poll, PollOption, PollVote, LoginLog, AdminLog
from application.auth_utils import log_admin_action
from application.moderator_routes import sanitize_input

# Create a Blueprint
admin_bp = Blueprint('admin_routes', __name__, url_prefix='/admin')

# registration function for admin routes
def register_admin_routes(app, get_db_connection, validate_student_id):
    @admin_bp.route('/')
    @admin_required
    def admin_dashboard():
        try:
            # Get all CCAs
            all_ccas = CCA.query.order_by(CCA.Name).all()
            # Retrieves all CCAs, ordered by name.
            log_admin_action(session["user_id"], "Admin login successful")
            # Get all students
            all_students = Student.query.order_by(Student.Name).all()
            
            # Get CCA memberships with details
            memberships = db.session.query(
                Student.Name.label('StudentName'),
                CCA.Name.label('CCAName'),
                CCAMembers.CCARole,
                Student.StudentId,
                CCA.CCAId,
                CCAMembers.MemberId
            ).join(User, CCAMembers.UserId == User.UserId).join(Student).join(CCA).order_by(CCA.Name, Student.Name).all()

            # Get students who need password setup (Password is NULL)
            students_needing_password_setup = db.session.query(
                Student.StudentId, Student.Name, Student.Email
            ).join(User).filter(User.Password == None).order_by(Student.Name).all()
            
            return render_template('admin_dashboard.html',
                                ccas=all_ccas,
                                students=all_students,
                                memberships=memberships,
                                students_needing_password_setup=students_needing_password_setup,
                                user_name=session['name'])
            
        except Exception as e:
            print(f"Admin dashboard error: {e}")
            log_admin_action(session["user_id"],f"[ERROR] Failed to render logs page: {str(e)}")
            flash('Error loading admin dashboard.', 'error')
            return render_template('admin_dashboard.html', 
                                ccas=[], students=[], memberships=[],
                                students_needing_password_setup=[],
                                user_name=session.get('name'))

    @admin_bp.route('/create-student', methods=['GET', 'POST'])
    @admin_required
    def create_student():
        if request.method == 'POST':
            student_id = request.form.get('student_id', '').strip()
            
            if not student_id:
                flash('Student ID is required.', 'error')
                log_admin_action(session["user_id"],f"[ERROR] Student ID is required.")
                return render_template('create_student.html')
            
            if not validate_student_id(student_id):
                flash('Student ID must be 7 digits.', 'error')
                log_admin_action(session["user_id"],f"[ERROR] Student ID must be 7 digits")
                return render_template('create_student.html')
            
            try:
                # Check admin access
                is_admin = db.session.query(User).filter_by(UserId=session["user_id"],SystemRole="admin").first() is not None 
                
                if not is_admin:
                    flash('Access denied.', 'error')
                    log_admin_action(session["user_id"],f"[ERROR] Access denied.")
                    print(f'DEBUG: Not admin, unauthorised to view.')
                    return redirect(url_for('student_routes.dashboard'))
            
                # Check if student exists
                student_record = Student.query.filter_by(StudentId=int(student_id)).first()
                
                # Finds a student by their student ID.
                if not student_record:
                    flash(f'Student ID {student_id} not found in student records. Please contact administration to add student to system first.', 'error')
                    log_admin_action(session["user_id"],f'Student ID  not found in student records. Please contact administration to add student to system first.')
                    return render_template('create_student.html')
                
                # Check if student already has a registered account
                existing_account = User.query.filter_by(StudentId=int(student_id)).first()
                
                # Checks if a user account already exists for the given student ID.
                if existing_account:
                    flash(f'Student {student_record.Name} (ID: {student_id}) already has a login account.', 'error')
                    log_admin_action(f'Student already has a login account.')
                    return render_template('create_student.html')
                
                # Create account with NULL password, student will set via email link
                new_user = User(Username=student_id, StudentId=int(student_id), Password=None, SystemRole='student')
                db.session.add(new_user)
                db.session.commit()

                log_admin_action(session["user_id"], f"Created login for student ID {student_id}")
                
                # Send password setup email immediately after successful account creation
                student_name = student_record.Name
                student_email = student_record.Email
                
                base_message = f'Login account created successfully for {student_name} (ID: {student_id})!'
                
                if student_email:
                    try:
                        # Generate password reset token and send setup email
                        token = email_service.generate_password_reset_token(student_id)
                        email_sent = email_service.send_student_credentials(
                            student_name=student_name,
                            student_email=student_email,
                            student_id=student_id,
                            temp_password=None  # No temp password needed
                        )
                        
                        if email_sent:
                            flash(f'{base_message} Password setup email sent to {student_email}. Student must set their password before they can login.', 'success')
                            log_admin_action(session["user_id"],f'Password setup email sent to student. Student must set their password before they can login.')
                        else:
                            flash(f'{base_message} However, email notification failed. Please provide password setup link manually.', 'warning')
                            log_admin_action(session["user_id"],f'However, email notification failed. Please provide password setup link manually.')
                    except Exception as e:
                        log_admin_action(session["user_id"],f"[ERROR] Failed to render logs page: {str(e)}")
                        print(f"Email sending error: {e}")
                        flash(f'{base_message} However, email notification failed. Please provide password setup link manually.', 'warning')
                else:
                    flash(f'{base_message} No email on file. Please provide password setup link manually.', 'warning')
                    log_admin_action(session["user_id"],f'However, email notification failed. Please provide password setup link manually.')
                return redirect(url_for('admin_routes.admin_dashboard'))
                
            except Exception as e:
                db.session.rollback()
                print(f"Create student account error: {e}")
                log_admin_action(session["user_id"],f"[ERROR] Failed to render logs page: {str(e)}")
                flash('Error creating student account. Please try again.', 'error')
                return render_template('create_student.html')
        
        return render_template('create_student.html')

    @admin_bp.route('/create-cca', methods=['GET', 'POST'])
    @admin_required
    def create_cca():
        if request.method == 'POST':

            name = sanitize_input(request.form.get('name', ''), max_length=100)
            description = sanitize_input(request.form.get('description', ''), max_length=1000)

            if not name:
                flash('CCA name is required.', 'error')
                log_admin_action(session["user_id"],'CCA name is required.')
                return render_template('create_cca.html')
            
            try:
                # Check admin access
                is_admin = db.session.query(User).filter_by(UserId=session["user_id"],SystemRole="admin").first() is not None 
                
                if not is_admin:
                    flash('Access denied.', 'error')
                    print(f'DEBUG: Not admin, unauthorised to view.')
                    log_admin_action(session["user_id"],'Access denied.')
                    return redirect(url_for('student_routes.dashboard'))
            
                # Check if CCA name already exists
                if CCA.query.filter_by(Name=name).first():
                    flash('CCA name already exists.', 'error')
                    log_admin_action(session["user_id"],'CCA name already exists.')
                    return render_template('create_cca.html')
                
                # Insert new CCA
                new_cca = CCA(Name=name, Description=description or '')
                db.session.add(new_cca)
                db.session.commit()

                log_admin_action(session["user_id"], f"Created CCA: {name}")

                flash(f'CCA "{name}" created successfully!', 'success')
                log_admin_action(session["user_id"],f'CCA created successfully!')
                return redirect(url_for('admin_routes.admin_dashboard'))
                
            except Exception as e:
                db.session.rollback()
                log_admin_action(session["user_id"],f"[ERROR] Failed to render logs page: {str(e)}")
                print(f"Create CCA error: {e}")
                flash('Error creating CCA. Please try again.', 'error')
                return render_template('create_cca.html')
        
        return render_template('create_cca.html')

    @admin_bp.route('/cca/<int:cca_id>')
    @admin_required
    def view_cca(cca_id):
        try:
            # Check admin access
            is_admin = db.session.query(User).filter_by(UserId=session["user_id"],SystemRole="admin").first() is not None 
                
            if not is_admin:
                flash('Access denied.', 'error')
                print(f'DEBUG: Not admin, unauthorised to view.')
                log_admin_action(session["user_id"],'Access denied.')
                return redirect(url_for('student_routes.dashboard'))
            
            # Get CCA details
            cca = CCA.query.get(cca_id)
            
            if not cca:
                flash('CCA not found.', 'error')
                log_admin_action(session["user_id"],'CCA not found.')
                return redirect(url_for('admin_routes.admin_dashboard'))
            
            # Get CCA members
            members = db.session.query(
                Student.StudentId, Student.Name, Student.Email, CCAMembers.CCARole, CCAMembers.MemberId, User.UserId
            ).join(User, CCAMembers.UserId == User.UserId).join(Student).filter(CCAMembers.CCAId == cca_id).order_by(Student.Name).all()
            
            # Get all students not in this CCA (for assignment)
            subquery = db.session.query(CCAMembers.UserId).filter(CCAMembers.CCAId == cca_id)
            available_students = db.session.query(Student.StudentId, Student.Name).join(User).filter(User.UserId.notin_(subquery)).order_by(Student.Name).all()
            
            return render_template('view_cca.html', 
                                 cca=cca, 
                                 members=members, 
                                 available_students=available_students)
            
        except Exception as e:
            print(f"View CCA error: {e}")
            log_admin_action(session["user_id"],f"[ERROR] Failed to render logs page: {str(e)}")
            flash('Error loading CCA details.', 'error')
            return redirect(url_for('admin_routes.admin_dashboard'))

    @admin_bp.route('/cca/<int:cca_id>/edit', methods=['POST'])
    @admin_required
    def edit_cca(cca_id):
        name = sanitize_input(request.form.get('name', ''), max_length=100)
        description = sanitize_input(request.form.get('description', ''), max_length=1000)

        if not name:
            flash('CCA name is required.', 'error')
            log_admin_action(session["user_id"],'CCA name is required.')
            return redirect(url_for('admin_routes.view_cca', cca_id=cca_id))
        
        try:
            # Check admin access
            is_admin = db.session.query(User).filter_by(UserId=session["user_id"],SystemRole="admin").first() is not None 
                
            if not is_admin:
                flash('Access denied.', 'error')
                print(f'DEBUG: Not admin, unauthorised to view.')
                log_admin_action(session["user_id"],f'DEBUG: Not admin, unauthorised to view.')
                return redirect(url_for('student_routes.dashboard'))
            
            # Check if new name conflicts with existing CCAs (excluding current one)
            if CCA.query.filter(CCA.Name == name, CCA.CCAId != cca_id).first():
                flash('CCA name already exists.', 'error')
                log_admin_action(session["user_id"],'CCA name already exists.')
                return redirect(url_for('admin_routes.view_cca', cca_id=cca_id))
            
            # Update CCA
            cca_to_update = CCA.query.get(cca_id)
            cca_to_update.Name = name
            cca_to_update.Description = description
            db.session.commit()

            log_admin_action(session["user_id"], f"Edited CCA ID {cca_id}: renamed to '{name}'")

            flash('CCA updated successfully!', 'success')
            log_admin_action(session["user_id"],'CCA updated successfully!')
            return redirect(url_for('admin_routes.view_cca', cca_id=cca_id))
            
        except Exception as e:
            db.session.rollback()
            print(f"Edit CCA error: {e}")
            log_admin_action(session["user_id"],f"[ERROR] Failed to render logs page: {str(e)}")
            flash('Error updating CCA.', 'error')
            return redirect(url_for('admin_routes.view_cca', cca_id=cca_id))

    @admin_bp.route('/cca/<int:cca_id>/add-student', methods=['POST'])
    @admin_required
    def add_student_to_cca(cca_id):
        student_id = request.form.get('student_id')
        role = request.form.get('role')

        if not all([student_id, role]):
            flash('Please select both student and role.', 'error')
            log_admin_action(session["user_id"],'Please select both student and role.')
            return redirect(url_for('admin_routes.view_cca', cca_id=cca_id))
        
        try:
            # Check admin access
            is_admin = db.session.query(User).filter_by(UserId=session["user_id"],SystemRole="admin").first() is not None 
                
            if not is_admin:
                flash('Access denied.', 'error')
                log_admin_action(session["user_id"],'Access denied.')
                print(f'DEBUG: Not admin, unauthorised to view.')
                return redirect(url_for('student_routes.dashboard'))
            
            # Finds a user by their student ID.
            user_result = User.query.filter_by(StudentId=int(student_id)).first()

            if not user_result:
                flash('Student not found.', 'error')
                log_admin_action(session["user_id"],'Student not found.')
                return redirect(url_for('admin_routes.view_cca', cca_id=cca_id))
            
            user_id = user_result.UserId
            
            # Adds a new member to a CCA.
            new_member = CCAMembers(UserId=user_id, CCAId=cca_id, CCARole=role)
            db.session.add(new_member)
            db.session.commit()

            log_admin_action(session["user_id"], f"Added student {student_id} to CCA {cca_id} as {role}")

            flash('Student added to CCA successfully!', 'success')
            return redirect(url_for('admin_routes.view_cca', cca_id=cca_id))
            
        except Exception as e:
            db.session.rollback()
            log_admin_action(session["user_id"],f"[ERROR] Failed to render logs page: {str(e)}")
            print(f"Add student to CCA error: {e}")
            flash('Error adding student to CCA.', 'error')
            return redirect(url_for('admin_routes.view_cca', cca_id=cca_id))

    @admin_bp.route('/cca/<int:cca_id>/remove-student/<int:member_id>', methods=['POST'])
    @admin_required
    def remove_student_from_cca(cca_id, member_id):
        try:
            # Check admin access
            is_admin = db.session.query(User).filter_by(UserId=session["user_id"],SystemRole="admin").first() is not None 
                
            if not is_admin:
                flash('Access denied.', 'error')
                log_admin_action(session["user_id"],'Access denied.')
                print(f'DEBUG: Not admin, unauthorised to view.')
                return redirect(url_for('student_routes.dashboard'))
            
            # Deletes a CCA membership entry by member and CCA ID.
            CCAMembers.query.filter_by(MemberId=member_id, CCAId=cca_id).delete()
            db.session.commit()

            log_admin_action(session["user_id"], f"Removed member {member_id} from CCA {cca_id}")

            flash('Student removed from CCA successfully!', 'success')
            log_admin_action(session["user_id"],'Student removed from CCA successfully!.')
            return redirect(url_for('admin_routes.view_cca', cca_id=cca_id))
            
        except Exception as e:
            db.session.rollback()
            log_admin_action(session["user_id"],f"[ERROR] Failed to render logs page: {str(e)}")
            print(f"Remove student from CCA error: {e}")
            flash('Error removing student from CCA.', 'error')
            return redirect(url_for('admin_routes.view_cca', cca_id=cca_id))

    @admin_bp.route('/cca/<int:cca_id>/delete', methods=['POST'])
    @admin_required
    def delete_cca(cca_id):
        try:
            # Check admin access
            is_admin = db.session.query(User).filter_by(UserId=session["user_id"],SystemRole="admin").first() is not None 
                
            if not is_admin:
                flash('Access denied.', 'error')
                log_admin_action(session["user_id"],'Access denied.')
                print(f'DEBUG: Not admin, unauthorised to view.')
                return redirect(url_for('student_routes.dashboard'))
            
            # Retrieves a CCA by its primary key.
            cca_result = CCA.query.get(cca_id)

            if not cca_result:
                flash('CCA not found.', 'error')
                log_admin_action(session["user_id"],'CCA not found.')
                return redirect(url_for('admin_routes.admin_dashboard'))
            
            cca_name = cca_result.Name
            
            # Deletes all memberships for a given CCA.
            CCAMembers.query.filter_by(CCAId=cca_id).delete()

            # Deletes all votes for polls associated with the CCA.
            poll_ids = [p.PollId for p in Poll.query.filter_by(CCAId=cca_id).all()]
            PollVote.query.filter(PollVote.PollId.in_(poll_ids)).delete(synchronize_session=False)

            # Deletes all options for polls associated with the CCA.
            PollOption.query.filter(PollOption.PollId.in_(poll_ids)).delete(synchronize_session=False)

            # Deletes all polls for a given CCA.
            Poll.query.filter_by(CCAId=cca_id).delete()

            # Deletes the CCA itself.
            CCA.query.filter_by(CCAId=cca_id).delete()
            
            db.session.commit()

            log_admin_action(session["user_id"], f"Deleted CCA '{cca_name}' (ID: {cca_id})")
            flash(f'CCA "{cca_name}" and all related data deleted successfully!', 'success')
            return redirect(url_for('admin_routes.admin_dashboard'))
            
        except Exception as e:
            db.session.rollback()
            print(f"Delete CCA error: {e}")
            log_admin_action(session["user_id"],f"[ERROR] Failed to render logs page: {str(e)}")
            flash('Error deleting CCA.', 'error')
            return redirect(url_for('admin_routes.view_cca', cca_id=cca_id))
    
    @admin_bp.route('/api/search-students')
    @admin_required
    def search_students():
        """API endpoint to search for students by name or student ID"""
        search_query = sanitize_input(request.args.get('q', ''), max_length=100)

        cca_id = request.args.get('cca_id', '')
        
        if not search_query or len(search_query) < 2:
            return {'students': []}
        
        try:
            # Check admin access
            is_admin = db.session.query(User).filter_by(UserId=session["user_id"],SystemRole="admin").first() is not None 
                
            if not is_admin:
                flash('Access denied.', 'error')
                print(f'DEBUG: Not admin, unauthorised to view.')
                log_admin_action(session["user_id"],f'DEBUG: Not admin, unauthorised to view.')
                return redirect(url_for('student_routes.dashboard'))
            
            # Searches for students not in a CCA by name or ID.
            search_pattern = f'%{search_query}%'
            subquery = db.session.query(CCAMembers.UserId).filter(CCAMembers.CCAId == cca_id)
            students = db.session.query(Student.StudentId, Student.Name, Student.Email).join(User).filter(
                db.or_(Student.Name.like(search_pattern), db.cast(Student.StudentId, db.String).like(search_pattern)),
                User.UserId.notin_(subquery)
            ).order_by(Student.Name).all()
            
            result = []
            for student in students:
                result.append({
                    'student_id': student.StudentId,
                    'name': student.Name,
                    'email': student.Email
                })
            
            return {'students': result}
            
        except Exception as e:
            print(f"Search students error: {e}")
            log_admin_action(session["user_id"],f"[ERROR] Failed to render logs page: {str(e)}")
            return {'error': 'Search failed'}, 500

    @admin_bp.route('/cca/<int:cca_id>/add-multiple-students', methods=['POST'])
    @admin_required
    def add_multiple_students_to_cca(cca_id):
        """Add multiple students to a CCA in a single operation"""
        student_ids = request.form.getlist('student_ids[]')
        role = request.form.get('role', 'member')
        
        if not student_ids:
            flash('Please select at least one student.', 'error')
            log_admin_action(session["user_id"],'Please select at least one student.')
            return redirect(url_for('admin_routes.view_cca', cca_id=cca_id))
        
        try:
            # Check admin access
            is_admin = db.session.query(User).filter_by(UserId=session["user_id"],SystemRole="admin").first() is not None 
                
            if not is_admin:
                flash('Access denied.', 'error')
                print(f'DEBUG: Not admin, unauthorised to view.')
                log_admin_action(session["user_id"],'Access denied.')
                return redirect(url_for('student_routes.dashboard'))
            
            # Retrieves user and student data for a list of student IDs.
            user_data = db.session.query(User.UserId, Student.StudentId, Student.Name).join(Student).filter(Student.StudentId.in_(student_ids)).all()
            
            # Check for students already in the CCA
            existing_members = db.session.query(CCAMembers.UserId).filter(
                CCAMembers.CCAId == cca_id,
                CCAMembers.UserId.in_([u.UserId for u in user_data])
            ).all()
            existing_user_ids = {em[0] for em in existing_members}

            new_members = []
            for user in user_data:
                if user.UserId not in existing_user_ids:
                    new_members.append({
                        'UserId': user.UserId,
                        'CCAId': cca_id,
                        'CCARole': role
                    })

            if new_members:
                db.session.bulk_insert_mappings(CCAMembers, new_members)
                db.session.commit()

                log_admin_action(session["user_id"], f"Bulk added {len(new_members)} students to CCA {cca_id} as {role}")

                flash(f'{len(new_members)} students added successfully!', 'success')
            else:
                flash('All selected students are already in this CCA.', 'info')
                log_admin_action(session["user_id"],'All selected students are already in this CCA.')

            return redirect(url_for('admin_routes.view_cca', cca_id=cca_id))
            
        except Exception as e:
            db.session.rollback()
            print(f"Add multiple students error: {e}")
            log_admin_action(session["user_id"],f"[ERROR] Failed to render logs page: {str(e)}")
            flash('An error occurred while adding students.', 'error')
            return redirect(url_for('admin_routes.view_cca', cca_id=cca_id))
    
    @admin_bp.route('/resend-password-setup/<int:student_id>', methods=['POST'])
    @admin_required
    def resend_password_setup_email(student_id):
        """Resend password setup email for a student who hasn't set their password yet"""
        try:
            # Check admin access
            is_admin = db.session.query(User).filter_by(UserId=session["user_id"],SystemRole="admin").first() is not None
            
            if not is_admin:
                flash('Access denied.', 'error')
                print(f'DEBUG: Not admin, unauthorised to view.')
                log_admin_action(session["user_id"],"Access denied.")
                return redirect(url_for('student_routes.dashboard'))
            
            # Retrieves student and user details for a specific student ID.
            student_record = db.session.query(
                Student.StudentId, Student.Name, Student.Email, User.Password
            ).join(User).filter(Student.StudentId == student_id).first()
            
            if not student_record:
                flash('Student not found.', 'error')
                log_admin_action(session["user_id"],"Student not found.")
                return redirect(url_for('admin_routes.admin_dashboard'))
            
            # Check if password is not already set
            if student_record.Password is not None:
                flash('Student has already set up their password.', 'info')
                log_admin_action(session["user_id"],"Student has already set up their password.")
                return redirect(url_for('admin_routes.admin_dashboard'))

            student_name = student_record.Name
            student_email = student_record.Email

            if student_email:
                try:
                    # Generate password reset token and send setup email
                    token = email_service.generate_password_reset_token(student_id)
                    email_sent = email_service.send_student_credentials(
                        student_name=student_name,
                        student_email=student_email,
                        student_id=student_id,
                        temp_password=None  # No temp password needed
                    )
                    
                    if email_sent:
                        flash(f'Password setup email resent to {student_email}.', 'success')
                        log_admin_action(session["user_id"],f'Password setup email resent to {student_email}.')
                    else:
                        flash('Email notification failed. Please try again.', 'error')
                        log_admin_action(session["user_id"],"Email notification failed. Please try again.")
                except Exception as e:
                    print(f"Email sending error: {e}")
                    log_admin_action(session["user_id"],f"[ERROR] Failed to render logs page: {str(e)}")
                    flash('Email notification failed. Please try again.', 'error')
            else:
                flash('No email on file for this student. Cannot send email.', 'warning')
                log_admin_action(session["user_id"],"No email on file for this student. Cannot send email")
            
            return redirect(url_for('admin_routes.admin_dashboard'))
            
        except Exception as e:
            print(f"Resend password setup error: {e}")
            log_admin_action(session["user_id"],f"[ERROR] Failed to render logs page: {str(e)}")
            flash('An error occurred. Please try again.', 'error')
            return redirect(url_for('admin_routes.admin_dashboard'))
    
    @admin_bp.route('/view-all-ccas')
    @admin_required
    def view_all_ccas():
        """Admin view to see all CCAs with member counts"""
        try:
            # Check admin access
            is_admin = db.session.query(User).filter_by(UserId=session["user_id"],SystemRole="admin").first() is not None 
                
            if not is_admin:
                flash('Access denied.', 'error')
                print(f'DEBUG: Not admin, unauthorised to view.')
                log_admin_action(session["user_id"],f'DEBUG: Not admin, unauthorised to view.')
                return redirect(url_for('student_routes.dashboard'))
            
            # Get all CCAs with member counts
            ccas = db.session.query(
                CCA.CCAId, CCA.Name, CCA.Description,
                db.func.count(CCAMembers.MemberId).label('MemberCount'),
                db.func.count(db.case((CCAMembers.CCARole == 'moderator', 1))).label('ModeratorCount')
            ).outerjoin(CCAMembers).group_by(CCA.CCAId, CCA.Name, CCA.Description).order_by(CCA.Name).all()
            
            return render_template('admin_view_all_ccas.html', 
                                ccas=ccas,
                                user_name=session.get('name'))
            
        except Exception as e:
            print(f"View all CCAs error: {e}")
            log_admin_action(session["user_id"],f"[ERROR] Failed to render logs page: {str(e)}")
            flash('Error loading CCA list.', 'error')
            return redirect(url_for('admin_routes.admin_dashboard'))

    @admin_bp.route('/view-all-polls')
    @admin_required
    def view_all_polls():
        """Admin view to see all polls in the system"""
        try:
            # Check admin access
            is_admin = db.session.query(User).filter_by(UserId=session["user_id"],SystemRole="admin").first() is not None 
                
            if not is_admin:
                flash('Access denied.', 'error')
                print(f'DEBUG: Not admin, unauthorised to view.')
                log_admin_action(session["user_id"],'Access denied.')
                return redirect(url_for('student_routes.dashboard'))
            
            # Retrieves all polls with CCA info and vote counts.
            polls_data = db.session.query(
                Poll.PollId,
                Poll.Question,
                Poll.QuestionType,
                Poll.StartDate,
                Poll.EndDate,
                Poll.IsAnonymous,
                Poll.IsActive,
                CCA.Name.label('CCAName'),
                db.func.count(PollVote.VoteId).label('VoteCount')
            ).join(CCA).outerjoin(PollVote).group_by(
                Poll.PollId, Poll.Question, Poll.QuestionType, Poll.StartDate, Poll.EndDate,
                Poll.IsAnonymous, Poll.IsActive, CCA.Name            ).order_by(Poll.EndDate.desc(), Poll.StartDate.desc()).all()
            
            processed_polls = []
            for poll in polls_data:
                # Calculate live status based on current time and poll end date
                live_is_active = False
                if poll.IsActive and poll.EndDate:
                    # Make sure both datetimes are timezone-aware for comparison
                    end_date = poll.EndDate
                    if end_date.tzinfo is None:
                        # If database datetime is naive, assume it's UTC
                        end_date = end_date.replace(tzinfo=timezone.utc)
                    
                    # Poll is live if it's marked as active AND hasn't ended yet
                    live_is_active = datetime.now(timezone.utc) <= end_date
                elif poll.IsActive and not poll.EndDate:
                    # If no end date is set, use the IsActive flag
                    live_is_active = poll.IsActive
                
                processed_polls.append({
                    'PollId': poll.PollId,
                    'Question': poll.Question,
                    'QuestionType': poll.QuestionType,
                    'StartDate': poll.StartDate.strftime('%Y-%m-%d %H:%M') if poll.StartDate else 'N/A',
                    'EndDate': poll.EndDate.strftime('%Y-%m-%d %H:%M') if poll.EndDate else 'N/A',
                    'IsAnonymous': poll.IsAnonymous,
                    'LiveIsActive': live_is_active,  # Use calculated live status
                    'CCAName': poll.CCAName,
                    'VoteCount': poll.VoteCount
                })
            
            return render_template('admin_view_all_polls.html', 
                                polls=processed_polls,
                                user_name=session['name'])
            
        except Exception as e:
            print(f"View all polls error: {e}")
            log_admin_action(session["user_id"],f"[ERROR] Failed to render logs page: {str(e)}")
            flash('Error loading polls.', 'error')
            return redirect(url_for('admin_routes.admin_dashboard'))

    @admin_bp.route('/logs')
    @admin_required
    def view_logs():
        # Get the total number of logs, categorized by type
        total_logs = db.session.query(AdminLog).count() + db.session.query(LoginLog).count()
        authentication_logs = db.session.query(LoginLog).count()
        authorization_logs = db.session.query(AdminLog).filter(AdminLog.Action == 'Authorization').count()
        data_changes_logs = db.session.query(AdminLog).filter(AdminLog.Action == 'Data Change').count()
        security_issues_logs = db.session.query(AdminLog).filter(AdminLog.Action == 'Security Issue').count()
        system_events_logs = db.session.query(AdminLog).filter(AdminLog.Action == 'System Event').count()

        # Get recent logs
        login_logs = (
            db.session.query(LoginLog, User)
            .outerjoin(User, LoginLog.UserId == User.UserId)
            .order_by(LoginLog.Timestamp.desc())
            .limit(50)
            .all()
        )

        admin_logs = (
            db.session.query(AdminLog, User)
            .outerjoin(User, AdminLog.AdminUserId == User.UserId)
            .order_by(AdminLog.Timestamp.desc())
            .limit(50)
            .all()
        )

        logs = sorted(
            [('auth', log, user) for log, user in login_logs] +
            [('admin', log, user) for log, user in admin_logs],
            key=lambda x: x[1].Timestamp,
            reverse=True
        )

        # Pass the counts and logs to the template
        return render_template('admin_logs.html', 
                            user_name=session['name'],
                            logs=logs,
                            total_logs=total_logs,
                            authentication_logs=authentication_logs,
                            authorization_logs=authorization_logs,
                            data_changes_logs=data_changes_logs,
                            security_issues_logs=security_issues_logs,
                            system_events_logs=system_events_logs)

    # Register the blueprint with the app
    app.register_blueprint(admin_bp)