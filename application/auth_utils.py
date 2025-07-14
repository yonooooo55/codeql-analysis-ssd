# application/auth_utils.py
from functools import wraps
from flask import session, redirect, url_for, flash, request
from application.models import db, User, CCAMembers
from application.models import LoginLog, db
from application.models import AdminLog, db

# ───────────────────────────────────────────────────────────
def _mfa_guard():
    """Redirect to /mfa-verify if this session skipped MFA."""
    if not session.get("mfa_authenticated"):
        flash("Please complete MFA verification first.", "warning")
        return redirect(url_for("misc_routes.mfa_verify"))

# ───────────────────────────────────────────────────────────
def login_required_with_mfa(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("misc_routes.login"))
        mfa_redirect = _mfa_guard()
        if mfa_redirect:
            return mfa_redirect
        return f(*args, **kwargs)
    return decorated

# ───────────────────────────────────────────────────────────
def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("misc_routes.login"))
        
        if session.get("role") != "admin":
            flash("Access denied.", "error")
            return redirect(url_for("student_routes.dashboard"))

        # MFA Check
        mfa_redirect = _mfa_guard()
        if mfa_redirect:
            return mfa_redirect

        try:
            # Check if user is an admin
            is_admin = db.session.query(User).filter_by(
                UserId=session["user_id"],
                SystemRole="admin"
            ).first() is not None

            if not is_admin:
                flash("Access denied.", "error")
                print(f'DEBUG: admin access denied')
                return redirect(url_for("student_routes.dashboard"))

        except Exception as e:
            print(f"[admin_required DB check error] {e}")
            flash("Error verifying privileges.", "error")
            return redirect(url_for("student_routes.dashboard"))

        return f(*args, **kwargs)
    return decorated

# ───────────────────────────────────────────────────────────
def moderator_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("misc_routes.login"))
        
        if session.get("role") not in ("moderator"):
            flash("Access denied.", "error")
            return redirect(url_for("student_routes.dashboard"))
        
        # MFA Check
        mfa_redirect = _mfa_guard()
        if mfa_redirect:
            return mfa_redirect
        
        try:
            # Check if user is a moderator in any CCA
            is_moderator = db.session.query(CCAMembers).filter_by(
                UserId=session['user_id'],
                CCARole='moderator'
            ).first() is not None

            if not is_moderator:
                flash("Access denied.", "error")
                print(f'DEBUG: moderator access denied.')
                return redirect(url_for("student_routes.dashboard"))

        except Exception as e:
            print(f"[moderator_required DB check error] {e}")
            flash("Error verifying moderator role.", "error")
            return redirect(url_for("student_routes.dashboard"))
        
        return f(*args, **kwargs)
    return decorated

# ───────────────────────────────────────────────────────────
def log_login_attempt(username, user_id, success, reason=None):
    log = LoginLog(
        Username=username,
        UserId=user_id,
        IPAddress=request.remote_addr,
        Success=success,
        Reason=reason
    )
    db.session.add(log)
    db.session.commit()

# ───────────────────────────────────────────────────────────
def log_admin_action(admin_user_id, action_desc):
    log = AdminLog(
        AdminUserId=admin_user_id,
        Action=action_desc,
        IPAddress=request.remote_addr
    )
    db.session.add(log)
    db.session.commit()