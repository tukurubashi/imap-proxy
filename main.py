from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import imaplib
import email
from email.header import decode_header
import re
from datetime import datetime, timezone
import traceback

app = FastAPI()

# CORS設定（どこからでもアクセス可能に）
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

class OTPRequest(BaseModel):
    host: str
    port: str = "993"
    user: str
    pass_: str = None  # 'pass' は予約語なのでエイリアス使用
    security: str = "SSL/TLS"
    targetEmail: str = ""
    deleteAfter: bool = False
    
    class Config:
        # JSONの 'pass' を 'pass_' にマッピング
        populate_by_name = True
        
    def __init__(self, **data):
        # 'pass' キーを 'pass_' に変換
        if 'pass' in data:
            data['pass_'] = data.pop('pass')
        super().__init__(**data)


def decode_mime_header(header_value):
    """MIMEエンコードされたヘッダーをデコード"""
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
    """メール本文から6桁のOTPを抽出"""
    # 6桁の数字を探す
    match = re.search(r'\b(\d{6})\b', body)
    if match:
        return match.group(1)
    return None


def get_message_date(msg) -> datetime | None:
    """メールの日付を取得"""
    date_str = msg.get('Date')
    if not date_str:
        return None
    try:
        # email.utils.parsedate_to_datetime を使用
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
        # IMAP接続
        if req.security == "SSL/TLS":
            mail = imaplib.IMAP4_SSL(req.host, int(req.port))
        else:
            mail = imaplib.IMAP4(req.host, int(req.port))
            if req.security == "STARTTLS":
                mail.starttls()
        
        # ログイン
        mail.login(req.user, req.pass_)
        
        # INBOXを選択
        mail.select("INBOX")
        
        # ポケモンセンターからのOTPメールを検索
        search_query = '(SUBJECT "ログイン用パスコードのお知らせ")'
        status, messages = mail.search(None, search_query)
        
        if status != "OK":
            return {"status": "error", "message": "検索エラー: " + str(status), "phase": "search"}
        
        mail_ids = messages[0].split()
        
        if not mail_ids:
            return {"status": "not_found", "message": "OTPメールが見つかりません"}
        
        # 最新のメールから確認
        latest_otp = None
        latest_date = None
        latest_subject = None
        latest_mail_id = None
        
        for mail_id in reversed(mail_ids[-10:]):  # 最新10件をチェック
            status, msg_data = mail.fetch(mail_id, "(RFC822)")
            if status != "OK":
                continue
            
            raw_email = msg_data[0][1]
            msg = email.message_from_bytes(raw_email)
            
            # 日付を取得
            msg_date = get_message_date(msg)
            
            # 件名をデコード
            subject = decode_mime_header(msg.get('Subject', ''))
            
            # 本文を取得
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
            
            # OTPを抽出
            otp = extract_otp_from_body(body)
            
            if otp:
                # 最新のものを保持
                if latest_date is None or (msg_date and msg_date > latest_date):
                    latest_otp = otp
                    latest_date = msg_date
                    latest_subject = subject
                    latest_mail_id = mail_id
        
        if latest_otp:
            # 削除オプションが有効なら削除
            if req.deleteAfter and latest_mail_id:
                try:
                    mail.store(latest_mail_id, '+FLAGS', '\\Deleted')
                    mail.expunge()
                except Exception as e:
                    print(f"メール削除エラー: {e}")
            
            # 何分前のメールか計算
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
