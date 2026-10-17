"""Flask application: admin panel + public setup page.

gunicorn runs create_app() as dbovpn on 127.0.0.1; nginx in front restricts
everything except /enroll/ and /static/ to the admin allowlist.
"""

import datetime
import functools
import os
import secrets
import time

from flask import (Flask, Response, abort, flash, g, redirect, render_template, request, session,
                   url_for)
from flask_wtf.csrf import CSRFError, CSRFProtect
from werkzeug.middleware.proxy_fix import ProxyFix

from dbovpn import admins, db, enroll, passwords, tokens, users
from dbovpn import config as config_mod
from dbovpn.ctl import CtlError, SessionControl
from dbovpn.mailer import Mailer
from dbovpn.privclient import PrivError, Privileged
from dbovpn.users import ServiceError
from dbovpn.web import i18n, qr
from dbovpn.textutil import human_size, redact_path, slug

SECRET_KEY_PATH = "/var/lib/dbo-vpn-gateway/flask-secret.key"
AUDIT_PAGE = 100


def load_secret_key(path):
    """Read the session signing key, creating it (0600) on first start."""
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        pass
    else:
        with os.fdopen(fd, "wb") as fh:
            fh.write(secrets.token_bytes(32))
    for _ in range(20):          # another worker may be writing it right now
        with open(path, "rb") as fh:
            key = fh.read()
        if len(key) == 32:
            return key
        time.sleep(0.1)
    raise RuntimeError("session key file %s is unreadable or truncated" % path)


class GatewayResponse(Response):
    # Werkzeug 2.0 would turn a relative Location into an absolute URL built from the
    # client's Host header; a relative Location is valid (RFC 7231) and cannot be steered.
    autocorrect_location_header = False


class GatewayFlask(Flask):
    response_class = GatewayResponse

    def log_exception(self, exc_info):
        # Flask's default message contains request.path, which would put setup tokens in the journal.
        self.logger.error("Exception on %s [%s]", redact_path(request.path), request.method, exc_info=exc_info)


def create_app(cfg=None, priv=None, ctl=None, mailer=None, db_path=None, secret_key=None):
    cfg = cfg or config_mod.load()
    priv = priv or Privileged()
    ctl = ctl or SessionControl()
    mailer = mailer or Mailer(cfg)

    app = GatewayFlask(__name__)
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=0)
    app.config.update(
        SECRET_KEY=secret_key or load_secret_key(os.environ.get("DBOVPN_SECRET_KEY", SECRET_KEY_PATH)),
        SESSION_COOKIE_NAME="dbovpn_session",
        SESSION_COOKIE_SECURE=True,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Strict",
        PERMANENT_SESSION_LIFETIME=datetime.timedelta(minutes=cfg.idle_timeout_minutes),
        SESSION_REFRESH_EACH_REQUEST=True,
        MAX_CONTENT_LENGTH=64 * 1024,
    )
    CSRFProtect(app)
    # Migrate once at startup; per-request connections skip it.
    db.connect(db_path).close()
    idle_seconds = cfg.idle_timeout_minutes * 60

    # Request plumbing ----------------------------------------------------------

    @app.before_request
    def before():
        g.conn = db.connect(db_path, migrate_schema=False)
        g.now = int(time.time())
        g.today = datetime.date.fromtimestamp(g.now)
        lang = request.args.get("lang")
        g.set_lang = lang if lang in cfg.languages else None
        cookie = request.cookies.get("lang")
        g.lang = g.set_lang or (cookie if cookie in cfg.languages else cfg.languages[0])
        g.admin = None

    @app.after_request
    def after(resp):
        if g.get("set_lang"):
            resp.set_cookie("lang", g.set_lang, max_age=365 * 86400, secure=True, httponly=True, samesite="Lax")
        resp.headers.setdefault("Cache-Control", "no-store")
        return resp

    @app.teardown_request
    def teardown(exc):
        conn = g.pop("conn", None)
        if conn is not None:
            conn.close()

    def t(key, **params):
        # Error handlers can run before before_request (e.g. a CSRF failure), so g.lang may be unset.
        return i18n.translate(g.get("lang") or cfg.languages[0], key, **params)

    def action_label(code):
        return i18n.action_label(g.get("lang") or cfg.languages[0], code)

    def detail_label(text):
        return i18n.detail_label(g.get("lang") or cfg.languages[0], text)

    def detail_title(text):
        return i18n.detail_title(text)

    @app.context_processor
    def inject():
        return {"t": t, "action_label": action_label, "detail_label": detail_label, "detail_title": detail_title, "now": g.get("now"),
                "is_locked": users.is_locked,
                "cert_ends_early": users.cert_ends_early, "needs_new_cert": users.needs_new_cert, "cfg": cfg, "admin": g.get("admin"), "lang": g.get("lang") or cfg.languages[0],
                "languages": cfg.languages, "today": g.get("today")}

    @app.template_filter("size")
    def fmt_size(value):
        return human_size(value)

    @app.template_filter("hm")
    def fmt_hm(value):
        """Lock end time: HH:MM today, otherwise YYYY-MM-DD HH:MM."""
        moment = datetime.datetime.fromtimestamp(int(value))
        return moment.strftime("%H:%M" if moment.date() == datetime.date.today() else "%Y-%m-%d %H:%M")

    @app.template_filter("ts")
    def fmt_ts(value):
        if not value:
            return ""
        return datetime.datetime.fromtimestamp(int(value)).strftime("%Y-%m-%d %H:%M")

    @app.errorhandler(CSRFError)
    def csrf_error(exc):
        return render_template("message.html", title=t("error"), text=t("csrf_failed")), 400

    @app.errorhandler(404)
    def not_found(exc):
        return render_template("message.html", title=t("error"), text=t("not_found")), 404

    def client_ip():
        return request.remote_addr or ""

    def ctx():
        return users.Context(cfg, g.conn, "admin:%s" % g.admin["username"], client_ip(), priv, ctl, mailer)

    def fail(exc):
        flash(t(exc.key, **exc.params), "error")

    # Admin session -------------------------------------------------------------

    def admin_required(view):
        @functools.wraps(view)
        def wrapper(*args, **kwargs):
            admin_id = session.get("admin_id")
            row = admins.get_by_id(g.conn, admin_id) if admin_id else None
            if (row is None or not row["enabled"] or session.get("sv") != row["session_version"]
                    or g.now - session.get("seen", 0) > idle_seconds):
                expired = admin_id is not None
                session.clear()
                if expired:
                    flash(t("session_expired", minutes=cfg.idle_timeout_minutes), "info")
                return redirect(url_for("login"))
            session["seen"] = g.now
            g.admin = row
            return view(*args, **kwargs)
        return wrapper

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            username = request.form.get("username", "").strip().lower()
            row, reason = admins.check_login(
                g.conn, cfg, username, request.form.get("password", ""), request.form.get("code", ""),
                passwords.verify_password, passwords.burn_time, g.now)
            target = username if config_mod.USERNAME_RE.match(username) else ""
            if row is None:
                db.audit(g.conn, "admin:%s" % (target or "unknown"), "admin.login_failed", target, reason,
                         client_ip(), g.now)
                flash(t("login_failed"), "error")
                return render_template("login.html", username=username), 401
            session.clear()
            session.permanent = True
            session["admin_id"] = row["id"]
            session["sv"] = row["session_version"]
            session["seen"] = g.now
            db.audit(g.conn, "admin:%s" % row["username"], "admin.login", row["username"], "", client_ip(), g.now)
            return redirect(url_for("dashboard"))
        return render_template("login.html", username="")

    @app.route("/logout", methods=["POST"])
    @admin_required
    def logout():
        g.conn.execute("UPDATE admins SET session_version = session_version + 1 WHERE id = ?", (g.admin["id"],))
        db.audit(g.conn, "admin:%s" % g.admin["username"], "admin.logout", g.admin["username"], "",
                 client_ip(), g.now)
        session.clear()
        return redirect(url_for("login"))

    # Panel pages ----------------------------------------------------------------

    def live_sessions():
        try:
            return ctl.list_sessions(), None
        except CtlError as exc:
            return [], str(exc)

    @app.route("/")
    @admin_required
    def dashboard():
        sessions, ctl_error = live_sessions()
        return render_template("dashboard.html", used=users.count(g.conn), max_users=cfg.max_users,
                               locked=users.locked_users(g.conn, g.now),
                               expiring=users.expiring_within(g.conn, g.today, 14),
                               sessions=sessions, ctl_error=ctl_error)

    @app.route("/users")
    @admin_required
    def user_list():
        rows = users.list_all(g.conn)
        return render_template("users.html", rows=rows, status=lambda r: users.status(r, g.today),
                               used=len(rows), max_users=cfg.max_users)

    @app.route("/users/new", methods=["GET", "POST"])
    @admin_required
    def user_new():
        low, high = users.expiry_bounds(cfg, g.today)
        form = {"username": "", "display_name": "", "email": "",
                "expires_on": users.default_expiry(cfg, g.today).isoformat()}
        if request.method == "POST":
            form = {k: request.form.get(k, "").strip() for k in form}
            form["username"] = form["username"].lower()
            try:
                row, raw, mail_ok = users.create_user(ctx(), form["username"], form["display_name"],
                                                      form["email"], form["expires_on"])
            except ServiceError as exc:
                fail(exc)
            else:
                return render_template("link.html", row=row, link=users.setup_link(cfg, raw), mail_ok=mail_ok)
        return render_template("user_new.html", form=form, low=low.isoformat(), high=high.isoformat(),
                               used=users.count(g.conn), max_users=cfg.max_users)

    def user_or_404(username):
        row = users.get(g.conn, username)
        if row is None:
            abort(404)
        return row

    @app.route("/users/<username>")
    @admin_required
    def user_detail(username):
        row = user_or_404(username)
        sessions, ctl_error = live_sessions()
        low, high = users.expiry_bounds(cfg, g.today)
        history = g.conn.execute("SELECT * FROM audit WHERE target = ? ORDER BY id DESC LIMIT 20",
                                 (username,)).fetchall()
        profile = cfg.profiles.get(row["profile"])
        return render_template("user_detail.html", row=row, status=users.status(row, g.today),
                               sessions=[s for s in sessions if s["common_name"] == username],
                               ctl_error=ctl_error, low=low.isoformat(), high=high.isoformat(),
                               history=history, profile=profile)

    @app.route("/users/<username>/<action>", methods=["POST"])
    @admin_required
    def user_action(username, action):
        user_or_404(username)
        c = ctx()
        try:
            if action == "enable":
                users.set_enabled(c, username, True)
                flash(t("done_enabled"), "ok")
            elif action == "disable":
                users.set_enabled(c, username, False)
                users.wait_sessions_gone(ctl, username)
                flash(t("done_disabled"), "ok")
            elif action == "expiry":
                users.set_expiry(c, username, request.form.get("expires_on", ""))
                flash(t("done_expiry"), "ok")
            elif action == "unlock":
                users.unlock_user(c, username)
                flash(t("done_unlocked"), "ok")
            elif action == "kick":
                killed = users.kick_user(c, username)
                users.wait_sessions_gone(ctl, username)
                flash(t("done_kick", n=killed), "ok")
            elif action == "reset":
                raw, mail_ok = users.reset_user(c, username)
                users.wait_sessions_gone(ctl, username)
                return render_template("link.html", row=users.get(g.conn, username),
                                       link=users.setup_link(cfg, raw), mail_ok=mail_ok)
            elif action == "delete":
                if request.form.get("confirm", "").strip() != username:
                    flash(t("delete_confirm_mismatch"), "error")
                else:
                    users.delete_user(c, username)
                    users.wait_sessions_gone(ctl, username)
                    flash(t("done_deleted", username=username), "ok")
                    return redirect(url_for("user_list"))
            else:
                abort(404)
        except ServiceError as exc:
            fail(exc)
        return redirect(url_for("user_detail", username=username))

    @app.route("/sessions")
    @admin_required
    def session_list():
        sessions, ctl_error = live_sessions()
        names = {r["username"]: r["display_name"] for r in users.list_all(g.conn)}
        return render_template("sessions.html", sessions=sessions, ctl_error=ctl_error, names=names)

    @app.route("/audit")
    @admin_required
    def audit_log():
        try:
            page = max(1, int(request.args.get("page", "1")))
        except ValueError:
            page = 1
        rows = g.conn.execute("SELECT * FROM audit ORDER BY id DESC LIMIT ? OFFSET ?",
                              (AUDIT_PAGE + 1, (page - 1) * AUDIT_PAGE)).fetchall()
        return render_template("audit.html", rows=rows[:AUDIT_PAGE], page=page, more=len(rows) > AUDIT_PAGE)

    # Setup links ----------------------------------------------------------------

    def enroll_view(kind, raw):
        token, subject = enroll.open_token(g.conn, kind, raw, g.now)
        if token is None:
            return render_template("message.html", title=t("link_invalid_title"), text=t("link_invalid")), 404
        flow_key = "enroll_%s" % kind
        error = None
        if request.method == "POST":
            step = request.form.get("step")
            try:
                if step == "password":
                    session[flow_key] = enroll.start(g.conn, token, subject, request.form.get("password", ""),
                                                     request.form.get("confirm", ""), passwords.hash_password,
                                                     g.now)
                    return redirect(request.path)
                if step == "totp":
                    enroll.finish(g.conn, kind, token, session.get(flow_key), request.form.get("code", ""),
                                  "%s:%s" % ("vpn" if kind == "vpn" else "admin", subject["username"]),
                                  client_ip(), g.now)
                    session.pop(flow_key, None)
                    session["enroll_done_%s" % kind] = tokens.hash_token(raw)
                    return render_template("enroll_done.html", kind=kind, raw=raw, subject=subject)
            except ServiceError as exc:
                error = t(exc.key, **exc.params)
                token, subject = enroll.open_token(g.conn, kind, raw, g.now)
                if token is None:
                    return render_template("message.html", title=t("link_invalid_title"),
                                           text=t("link_invalid")), 404
        nonce = session.get(flow_key)
        if token["flow_nonce"] and nonce and secrets.compare_digest(token["flow_nonce"], nonce):
            secret, uri, issuer = enroll.provisioning(cfg, kind, token)
            return render_template("enroll_totp.html", kind=kind, subject=subject, secret=secret,
                                   qr=qr.qr_data_uri(uri), issuer=issuer, error=error)
        return render_template("enroll_password.html", kind=kind, subject=subject, error=error,
                               min_length=passwords.MIN_LENGTH)

    @app.route("/enroll/<raw>", methods=["GET", "POST"])
    def enroll_vpn(raw):
        return enroll_view("vpn", raw)

    @app.route("/admin-enroll/<raw>", methods=["GET", "POST"])
    def enroll_admin(raw):
        return enroll_view("admin", raw)

    @app.route("/enroll/<raw>/download", methods=["POST"])
    def enroll_download(raw):
        token = tokens.find_completed(g.conn, "vpn", raw, g.now)
        done = session.get("enroll_done_vpn")
        if token is None or not done or not secrets.compare_digest(done, tokens.hash_token(raw)):
            return render_template("message.html", title=t("link_invalid_title"), text=t("download_gone")), 404
        vctx = users.Context(cfg, g.conn, "vpn:%s" % token["subject"], client_ip(), priv, ctl, mailer)
        try:
            # Adopted/legacy, passphrase-protected or too short-lived certificates are
            # replaced here, so the profile always outlives the account.
            users.ensure_fresh_cert(vctx, token["subject"])
            content = priv.build_ovpn(token["subject"])
        except ServiceError as exc:
            if exc.key == "cert_renew_busy":
                return render_template("message.html", title=t("error"), text=t(exc.key)), 409
            return render_template("message.html", title=t("error"), text=t("download_failed")), 500
        except PrivError as exc:
            db.audit(g.conn, "vpn:%s" % token["subject"], "profile.download_failed", token["subject"],
                     db.detail("error", error=str(exc)),
                     client_ip(), g.now)
            return render_template("message.html", title=t("error"), text=t("download_failed")), 500
        db.audit(g.conn, "vpn:%s" % token["subject"], "profile.download", token["subject"], "", client_ip(), g.now)
        filename = "%s-%s.ovpn" % (slug(cfg.customer_name), token["subject"])
        return Response(content, mimetype="application/x-openvpn-profile",
                        headers={"Content-Disposition": 'attachment; filename="%s"' % filename,
                                 "Cache-Control": "no-store"})

    return app
