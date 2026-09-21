from flask import render_template, request, session

# Every route except login/logout/static used to repeat this same check as its
# first line (or, in ~13 routes, nested inside a try:) - see the audit in the
# Phase 2 plan. Centralizing it here removes that duplication without
# changing behavior: it returns the exact same login template the per-route
# checks did.
EXEMPT_ENDPOINTS = {"auth.do_login", "auth.logout", "static"}


def register_auth_guard(app):
    """Registers the single before_request hook that replaces the
    copy-pasted `if not session.get('logged_in')` checks."""

    @app.before_request
    def _require_login():
        if request.endpoint in EXEMPT_ENDPOINTS:
            return None
        if not session.get("logged_in"):
            return render_template("login.html")
        return None

    # Note: a second check - redirecting to engagement selection when
    # session['engagement_path'] isn't set yet - was considered here too,
    # since most routes implicitly assume it's already set. It was left out
    # of this pass: flask_files/table_class.py's `model=event` path shows at
    # least one route family (email-event/global tables, not per-engagement)
    # is deliberately reachable without an engagement selected, and there's
    # no way to verify the full set of such routes without running the app
    # end-to-end. Revisit once that can be checked properly.
