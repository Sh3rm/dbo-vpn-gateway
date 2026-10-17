"""Outbound mail through the configured relay (port 25, no auth, STARTTLS when offered).

A mail failure is reported to the caller as False plus a reason, never raised:
the caller audits it and carries on.
"""

import logging
import os
import smtplib
import socket
import ssl
import string
from email.message import EmailMessage
from email.utils import formatdate, make_msgid

log = logging.getLogger(__name__)

TEMPLATE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "mail_templates")


def render(language, name, values):
    """Return (subject, body) from mail_templates/<language>/<name>.txt.

    The first line is 'Subject: ...', then a blank line, then the body.
    Placeholders use string.Template syntax ($name).
    """
    path = os.path.join(TEMPLATE_DIR, language, name + ".txt")
    with open(path, "r", encoding="utf-8") as fh:
        text = fh.read()
    head, _, body = text.partition("\n\n")
    if not head.startswith("Subject: "):
        raise ValueError("template %s has no Subject line" % path)
    subject = string.Template(head[len("Subject: "):].strip()).substitute(values)
    return subject, string.Template(body).substitute(values)


class Mailer(object):
    def __init__(self, cfg, timeout=20):
        self.cfg = cfg
        self.timeout = timeout

    def send(self, recipients, subject, body):
        """Send a plain-text mail. Returns (ok, error_text)."""
        if isinstance(recipients, str):
            recipients = [recipients]
        recipients = [r for r in recipients if r]
        if not recipients:
            return False, "no recipients"
        msg = EmailMessage()
        msg["From"] = self.cfg.sender
        msg["To"] = ", ".join(recipients)
        msg["Subject"] = subject
        msg["Date"] = formatdate(localtime=True)
        msg["Message-ID"] = make_msgid(domain=self.cfg.public_hostname)
        msg.set_content(body)
        try:
            with smtplib.SMTP(self.cfg.relay_host, self.cfg.relay_port, timeout=self.timeout) as smtp:
                smtp.ehlo()
                if smtp.has_extn("starttls"):
                    context = ssl.create_default_context()
                    if not self.cfg.tls_verify:
                        context.check_hostname = False
                        context.verify_mode = ssl.CERT_NONE
                    smtp.starttls(context=context)
                    smtp.ehlo()
                smtp.send_message(msg)
        except (smtplib.SMTPException, OSError, socket.timeout, ssl.SSLError) as exc:
            log.warning("mail to %s failed: %s", ", ".join(recipients), exc)
            return False, str(exc)[:300]
        return True, ""

    def send_template(self, recipients, name, values, language=None):
        subject, body = render(language or self.cfg.mail_language, name, values)
        return self.send(recipients, subject, body)
