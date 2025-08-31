from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
import sqlite3
import re
from typing import Optional

app = FastAPI()

# FastAPIの自動401を止めて、仕様どおりの文言で返す
security = HTTPBasic(auto_error=False)

DB_PATH = "users.db"
USER_ID_RE = re.compile(r"^[A-Za-z0-9]{6,20}$")
PASSWORD_RE = re.compile(r"^[A-Za-z0-9]{8,20}$")

# ====== DB helpers ======


def get_conn():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_conn()
    try:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
              user_id  TEXT PRIMARY KEY,
              password TEXT NOT NULL,
              nickname TEXT,
              comment  TEXT
            )
        """)
        conn.commit()
    finally:
        conn.close()


def db_get_user(user_id: str) -> Optional[sqlite3.Row]:
    conn = get_conn()
    try:
        cur = conn.execute(
            "SELECT user_id,password,nickname,comment FROM users WHERE user_id=?",
            (user_id,)
        )
        return cur.fetchone()
    finally:
        conn.close()


def db_create_user(user_id: str, password: str, nickname: Optional[str], comment: Optional[str]):
    conn = get_conn()
    try:
        conn.execute(
            "INSERT INTO users(user_id,password,nickname,comment) VALUES(?,?,?,?)",
            (user_id, password, nickname, comment)
        )
        conn.commit()
    finally:
        conn.close()


def db_update_user(user_id: str, nickname: Optional[str], comment: Optional[str]):
    conn = get_conn()
    try:
        conn.execute(
            "UPDATE users SET nickname=?, comment=? WHERE user_id=?",
            (nickname, comment, user_id)
        )
        conn.commit()
    finally:
        conn.close()


def db_delete_user(user_id: str):
    conn = get_conn()
    try:
        conn.execute("DELETE FROM users WHERE user_id=?", (user_id,))
        conn.commit()
    finally:
        conn.close()

# ====== 起動時初期化（テスト用アカウントのシード含む） ======


@app.on_event("startup")
def on_startup():
    init_db()
    # 仕様に記載のテスト用アカウント
    seed_uid = "TaroYamada"
    seed_pw = "PaSSwd4TY"
    if db_get_user(seed_uid) is None:
        # 初期nicknameは user_id と同値でも可だが、課題の例に合わせてセット
        db_create_user(seed_uid, seed_pw, "たろー", "僕は元気です")

# ====== 共通 ======


def json400(msg: str, cause: str):
    return JSONResponse(status_code=400, content={"message": msg, "cause": cause})


def auth_user(creds: HTTPBasicCredentials | None = Depends(security)) -> str:
    # 失敗時は常に「Authentication failed」
    if creds is None or creds.username is None or creds.password is None:
        raise HTTPException(status_code=401, detail={
                            "message": "Authentication failed"})
    uid, pw = creds.username, creds.password
    row = db_get_user(uid)
    if row is None or row["password"] != pw:
        raise HTTPException(status_code=401, detail={
                            "message": "Authentication failed"})
    return uid

# ====== /signup ======


@app.post("/signup")
async def signup(req: Request):
    # Pydanticの422を避け、明示的に400を返す
    try:
        data = await req.json()
    except Exception:
        return json400("Account creation failed", "Required user_id and password")

    uid = data.get("user_id")
    pw = data.get("password")

    if not uid or not pw:
        return json400("Account creation failed", "Required user_id and password")
    if not (6 <= len(uid) <= 20) or not (8 <= len(pw) <= 20):
        return json400("Account creation failed", "Input length is incorrect")
    if not USER_ID_RE.fullmatch(uid) or not PASSWORD_RE.fullmatch(pw):
        return json400("Account creation failed", "Incorrect character pattern")
    if db_get_user(uid) is not None:
        return json400("Account creation failed", "Already same user_id is used")

    # 初期nicknameは user_id、commentは未設定(None)
    db_create_user(uid, pw, uid, None)
    return {
        "message": "Account successfully created",
        "user": {"user_id": uid, "nickname": uid}
    }

# ====== GET /users/{user_id} ======


@app.get("/users/{user_id}")
def get_user(user_id: str, _: str = Depends(auth_user)):
    row = db_get_user(user_id)
    if row is None:
        raise HTTPException(status_code=404, detail={
                            "message": "No user found"})
    nickname = row["nickname"] if row["nickname"] is not None else row["user_id"]
    body = {
        "message": "User details by user_id",
        "user": {"user_id": row["user_id"], "nickname": nickname}
    }
    if row["comment"] is not None:
        body["user"]["comment"] = row["comment"]
    return JSONResponse(
        status_code=200,
        content=body,
        headers={"Cache-Control": "private, max-age=60"}
    )

# ====== PATCH /users/{user_id} ======


class PatchBody(BaseModel):
    nickname: str | None = Field(default=None, max_length=30)
    comment: str | None = Field(default=None, max_length=100)


@app.patch("/users/{user_id}")
def patch_user(user_id: str, body: PatchBody, authed: str = Depends(auth_user)):
    # まず本人チェック（テストは403を期待）
    if authed != user_id:
        raise HTTPException(status_code=403, detail={
                            "message": "No permission for update"})
    row = db_get_user(user_id)
    if row is None:
        raise HTTPException(status_code=404, detail={
                            "message": "No user found"})

    if body.nickname is None and body.comment is None:
        return JSONResponse(status_code=400, content={
            "message": "User updation failed", "cause": "Required nickname or comment"
        })

    def invalid(s: Optional[str]) -> bool:
        if s is None:
            return False
        # 空文字はクリア可。その他はASCII可視文字のみ
        return s != "" and not all(32 <= ord(c) <= 126 for c in s)

    if invalid(body.nickname) or invalid(body.comment):
        return JSONResponse(status_code=400, content={
            "message": "User updation failed", "cause": "Invalid nickname or comment"
        })

    new_nickname = row["nickname"]
    new_comment = row["comment"]
    if body.nickname is not None:
        new_nickname = None if body.nickname == "" else body.nickname
    if body.comment is not None:
        new_comment = None if body.comment == "" else body.comment

    db_update_user(user_id, new_nickname, new_comment)

    return {
        "message": "User successfully updated",
        "user": {"nickname": new_nickname, "comment": new_comment}
    }

# ====== POST /close ======


@app.post("/close")
def close_account(authed: str = Depends(auth_user)):
    db_delete_user(authed)
    return {"message": "Account and user successfully removed"}

# ====== エラーハンドラ（仕様どおりのJSONで返す） ======


@app.exception_handler(HTTPException)
async def http_exc_handler(request: Request, exc: HTTPException):
    if isinstance(exc.detail, dict):
        return JSONResponse(status_code=exc.status_code, content=exc.detail)
    return JSONResponse(status_code=exc.status_code, content={"message": str(exc.detail)})
