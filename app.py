from flask import Flask, request, jsonify
import re
import smtplib
import dns.resolver
import socket
import logging
import traceback
from datetime import datetime

# === Logging Configuration ===
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

# === Constants ===
SMTP_CLIENT_HOST = "ec2-54-226-246-82.compute-1.amazonaws.com"
FIXED_SENDER = "webmaster@datagateway1.shop"

# === Custom Exceptions ===
class InvalidInputException(Exception):
    def __init__(self, message, code):
        super().__init__(message)
        self.code = code

class DatabaseException(Exception):
    def __init__(self, message, code):
        super().__init__(message)
        self.code = code

# === Data Models ===
class EmailVerificationResponse:
    def __init__(self, email, deliverable, message):
        self.email = email
        self.deliverable = deliverable
        self.message = message

class EmailVerificationResponseModel:
    def __init__(self, email, deliverable, message):
        self.email = email
        self.deliverable = deliverable
        self.message = message

    def to_dict(self):
        return {
            "email": self.email,
            "deliverable": self.deliverable,
            "message": self.message,
        }

# === Email Verification Logic ===
def load_throwable_domains():
    return {"mailinator.com", "tempmail.com"}

def is_catch_all_domain(domain, mx_host):
    try:
        test_email = f"random{int(datetime.now().timestamp())}@{domain}"
        server = smtplib.SMTP(mx_host, 25, timeout=10)
        server.ehlo_or_helo_if_needed()
        server.mail(FIXED_SENDER)
        code, _ = server.rcpt(test_email)
        server.quit()
        return code == 250
    except Exception:
        return False

def verify_email(email):
    start_time = datetime.now()
    logger.info(f"START verification for: {email} at {start_time}")

    deliverable = False
    response_message = ""

    if not re.match(r"^[\w\.-]+@[\w\.-]+\.\w+$", email):
        raise InvalidInputException("Invalid email syntax.", "INVALID_SYNTAX")

    domain = email.split("@")[1]

    if domain.lower() in load_throwable_domains():
        raise InvalidInputException("Domain is a known throwable domain.", "THROWABLE_DOMAIN")

    try:
        answers = dns.resolver.resolve(domain, 'MX')
        mx_record = sorted(answers, key=lambda r: r.preference)[0]
        mx_host = str(mx_record.exchange).rstrip('.')
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException) as e:
        raise DatabaseException(f"Error parsing domain: {e}", "DOMAIN_PARSE_ERROR")

    if is_catch_all_domain(domain, mx_host):
        user_exists = False
        vrfy_msg = ""
        try:
            server = smtplib.SMTP(mx_host, 25, timeout=10)
            server.ehlo_or_helo_if_needed()
            code, reply = server.docmd("VRFY", email)
            if code == 250:
                user_exists = True
                vrfy_msg = f"VRFY succeeded: {reply.decode()}"
            else:
                vrfy_msg = f"VRFY failed: {reply.decode()}"
            server.quit()
        except (smtplib.SMTPException, socket.error) as e:
            vrfy_msg = f"VRFY exception: {e}"

        return EmailVerificationResponse(email, user_exists, f"Catch-all domain. VRFY result: {vrfy_msg}")

    try:
        client = smtplib.SMTP(mx_host, 25, timeout=10)
        client.ehlo_or_helo_if_needed()
        senders = [FIXED_SENDER, "info@technicalservice.tech"]
        mail_from_success = False
        used_sender = ""

        for sender in senders:
            code, _ = client.mail(sender)
            if code == 250:
                mail_from_success = True
                used_sender = sender
                break

        if not mail_from_success:
            client.quit()
            raise DatabaseException("MAIL FROM command failed.", "SMTP_MAILFROM_FAIL")

        code, reply = client.rcpt(email)
        if code in (250, 251):
            deliverable = True
            response_message = f"Email is deliverable (sender used: {used_sender})"
        else:
            response_message = f"RCPT TO command rejected: {reply.decode()}"
        client.quit()
    except (smtplib.SMTPException, socket.error) as e:
        raise DatabaseException(f"SMTP error: {e}", "SMTP_ERROR")

    return EmailVerificationResponse(email, deliverable, response_message)

# === Flask App Setup ===
app = Flask(__name__)

@app.route("/", methods=["POST"])
def verify_email_endpoint():
    try:
        data = request.get_json()
        if not data or "email" not in data:
            return jsonify({"error": "Missing email field in request"}), 400

        email = data["email"]
        result = verify_email(email)
        response_model = EmailVerificationResponseModel(
            result.email, result.deliverable, result.message
        )
        return jsonify(response_model.to_dict()), 200

    except InvalidInputException as e:
        return jsonify({"error": f"{e.code}: {e}"}), 400
    except DatabaseException as e:
        return jsonify({"error": f"{e.code}: {e}"}), 500
    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": f"UNEXPECTED_ERROR: {e}"}), 500

if __name__ == "__main__":
    app.run(debug=True)
