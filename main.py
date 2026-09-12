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
    debug: bool = False
    sinceTime: str = ""
    
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


def parse_since_time(since_str: str) -> datetime | None:
    if not since_str:
        return None
    try:
        dt = datetime.fromisoformat(since_str.replace('Z', '+00:00'))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except:
        return None


@app.get("/")
def root():
    return {"status": "ok", "service": "IMAP OTP Proxy"}


@app.post("/api/otp")
def get_otp(req: OTPRequest):
    mail = None
    debug_info = []
    try:
        if req.security == "SSL/TLS":
            mail = imaplib.IMAP4_SSL(req.host, int(req.port))
        else:
            mail = imaplib.IMAP4(req.host, int(req.port))
            if req.security == "STARTTLS":
                mail.starttls()
        
        mail.login(req.user, req.pass_)
        mail.select("INBOX")
        
        status, messages = mail.search(None, 'ALL')
        
        if status != "OK":
            return {"status": "error", "message": "検索エラー: " + str(status), "phase": "search"}
        
        mail_ids = messages[0].split()
        since_dt = parse_since_time(req.sinceTime)
        
        debug_info.append(f"総メール数: {len(mail_ids)}")
        debug_info.append(f"targetEmail: {req.targetEmail}")
        debug_info.append(f"sinceTime: {req.sinceTime}")
        
        if not mail_ids:
            return {"status": "not_found", "message": "メールが見つかりません", "debug": debug_info}
        
        latest_otp = None
        latest_date = None
        latest_subject = None
        latest_mail_id = None
        
        for mail_id in reversed(mail_ids[-100:]):
            try:
                status, msg_data = mail.fetch(mail_id, "(RFC822)")
                if status != "OK" or not msg_data or not msg_data[0]:
                    continue
                
                raw_email = msg_data[0][1] if isinstance(msg_data[0], tuple) else None
                if not raw_email:
                    continue
                    
                msg = email.message_from_bytes(raw_email)
                
                from_header = msg.get('From', '')
                to_header = msg.get('To', '')
                subject = decode_mime_header(msg.get('Subject', ''))
                
                # ポケセンからのメールかチェック
                if 'pokemoncenter-online.com' not in from_header.lower():
                    continue
                
                # パスコードのメールかチェック
                if 'パスコード' not in subject:
                    continue
                
                # targetEmailチェック（Toヘッダー）
                if req.targetEmail:
                    if req.targetEmail.lower() not in to_header.lower():
                        debug_info.append(f"To不一致: {to_header[:80]}")
                        continue
                    debug_info.append(f"To一致: {to_header[:80]}")
                
                msg_date = get_message_date(msg)
                
                # sinceTime以降のメールだけ
                if since_dt and msg_date:
                    if msg_date.tzinfo is None:
                        msg_date = msg_date.replace(tzinfo=timezone.utc)
                    if msg_date < since_dt:
                        debug_info.append(f"古いのでスキップ: {msg_date}")
                        continue
                
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
                    debug_info.append(f"OTP: {otp}, Date: {msg_date}")
                    if latest_date is None or (msg_date and msg_date > latest_date):
                        latest_otp = otp
                        latest_date = msg_date
                        latest_subject = subject
                        latest_mail_id = mail_id
            except Exception as e:
                debug_info.append(f"エラー: {str(e)}")
                continue
        
        if latest_otp:
            if req.deleteAfter and latest_mail_id:
                try:
                    mail.store(latest_mail_id, '+FLAGS', '\\Deleted')
                    mail.expunge()
                except Exception as e:
                    debug_info.append(f"削除エラー: {e}")
            
            age_minutes = None
            if latest_date:
                now = datetime.now(timezone.utc)
                if latest_date.tzinfo is None:
                    latest_date = latest_date.replace(tzinfo=timezone.utc)
                age_minutes = round((now - latest_date).total_seconds() / 60, 1)
            
            result = {
                "status": "success",
                "code": latest_otp,
                "ageMinutes": age_minutes,
                "messageDate": latest_date.isoformat() if latest_date else None,
                "subject": latest_subject,
                "deleted": req.deleteAfter
            }
            if req.debug:
                result["debug"] = debug_info
            return result
        
        return {"status": "not_found", "message": "OTPコードが見つかりません", "debug": debug_info}
    
    except imaplib.IMAP4.error as e:
        return {"status": "error", "message": f"IMAP エラー: {str(e)}", "phase": "imap", "debug": debug_info}
    except Exception as e:
        traceback.print_exc()
        return {"status": "error", "message": str(e), "phase": "unknown", "debug": debug_info}
    finally:
        if mail:
            try:
                mail.logout()
            except:
                pass
