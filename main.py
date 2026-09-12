from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import imaplib
import email
from email.header import decode_header
import re
from datetime import datetime, timezone
import traceback

app = FastAPI()

class OTPRequest(BaseModel):
    host: str
    port: str = "993"
    user: str
    pass_: str = None
    security: str = "SSL/TLS"
    targetEmail: str = ""
    deleteAfter: bool = False
    
    class Config:
        populate_by_name = True
        
    def __init__(self, **data):
        if 'pass' in data:
            data['pass_'] = data.pop('pass')
        super().__init__(**data)


@app.middleware("http")
async def add_cors_headers(request: Request, call_next):
    if request.method == "OPTIONS":
        return JSONResponse(
            content={},
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "*",
                "Access-Control-Allow-Headers": "*",
            }
        )
    response = await call_next(request)
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "*"
    response.headers["Access-Control-Allow-Headers"] = "*"
    return response


def decode_mime_header(header_value):
    if not header_value:
        return ""
    decoded_parts = decode_header(header_value)
    result = []
    for part, charset in decoded_parts:
        if isinstance(part, bytes):
            result.append(part.decode(charset or 'utf-8', errors='replace'))
        else:
            result.append(part)
    return ''.join(result)


def extract_otp_from_body(body: str) -> str | None:
    match = re.search(r'\b(\d{6})\b', body)
    if match:
        return match.group(1)
    return None


def get_message_date(msg) -> datetime | None:
    date_str = msg.get('Date')
    if not date_str:
        return None
    try:
        from email.utils import parsedate_to_datetime
        return parsedate_to_datetime(date_str)
    except:
        return None


@app.get("/")
def root():
    return {"status": "ok", "service": "IMAP OTP Proxy"}


@app.post("/api/otp")
def get_otp(req: OTPRequest):
    mail = None
    try:
        if req.security == "SSL/TLS":
            mail = imaplib.IMAP4_SSL(req.host, int(req.port))
        else:
            mail = imaplib.IMAP4(req.host, int(req.port))
            if req.security == "STARTTLS":
                mail.starttls()
        
        mail.login(req.user, req.pass_)
        mail.select("INBOX")
        
        search_query = '(SUBJECT "ログイン用パスコードのお知らせ")'
        status, messages = mail.search(None, search_query)
        
        if status != "OK":
            return {"status": "error", "message": "検索エラー: " + str(status), "phase": "search"}
        
        mail_ids = messages[0].split()
        
        if not mail_ids:
            return {"status": "not_found", "message": "OTPメールが見つかりません"}
        
        latest_otp = None
        latest_date = None
        latest_subject = None
        latest_mail_id = None
        
        for mail_id in reversed(mail_ids[-10:]):
            status, msg_data = mail.fetch(mail_id, "(RFC822)")
            if status != "OK":
                continue
            
            raw_email = msg_data[0][1]
            msg = email.message_from_bytes(raw_email)
            msg_date = get_message_date(msg)
            subject = decode_mime_header(msg.get('Subject', ''))
            
            body = ""
            if msg.is_multipart():
                for part in msg.walk():
                    content_type = part.get_content_type()
                    if content_type == "text/plain":
                        payload = part.get_payload(decode=True)
                        if payload:
                            charset = part.get_content_charset() or 'utf-8'
                            body = payload.decode(charset, errors='replace')
                            break
            else:
                payload = msg.get_payload(decode=True)
                if payload:
                    charset = msg.get_content_charset() or 'utf-8'
                    body = payload.decode(charset, errors='replace')
            
            otp = extract_otp_from_body(body)
            
            if otp:
                if latest_date is None or (msg_date and msg_date > latest_date):
                    latest_otp = otp
                    latest_date = msg_date
                    latest_subject = subject
                    latest_mail_id = mail_id
        
        if latest_otp:
            if req.deleteAfter and latest_mail_id:
                try:
                    mail.store(latest_mail_id, '+FLAGS', '\\Deleted')
                    mail.expunge()
                except Exception as e:
                    print(f"メール削除エラー: {e}")
            
            age_minutes = None
            if latest_date:
                now = datetime.now(timezone.utc)
                if latest_date.tzinfo is None:
                    latest_date = latest_date.replace(tzinfo=timezone.utc)
                age_minutes = round((now - latest_date).total_seconds() / 60, 1)
            
            return {
                "status": "success",
                "code": latest_otp,
                "ageMinutes": age_minutes,
                "messageDate": latest_date.isoformat() if latest_date else None,
                "subject": latest_subject,
                "deleted": req.deleteAfter
            }
        
        return {"status": "not_found", "message": "OTPコードが見つかりません"}
    
    except imaplib.IMAP4.error as e:
        return {"status": "error", "message": f"IMAP エラー: {str(e)}", "phase": "imap"}
    except Exception as e:
        traceback.print_exc()
        return {"status": "error", "message": str(e), "phase": "unknown"}
    finally:
        if mail:
            try:
                mail.logout()
            except:
                pass
