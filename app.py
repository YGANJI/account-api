from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
import re
import sqlite3
from typing import Optional

app = FastAPI()
security = HTTPBasic(auto_error=False)

DB_PATH = "users.db"

USER_ID_RE = re.compile(r"^[A-Za-z0-9]{6,20}$")
PASSWORD_RE = re.compile(r"^[A-Za-z0-9]{8,20}$")

# ---------- DB Helpers ----------


def get_conn():
    # SQLiteはスレッド制約が厳しいので都度コネクションを開く
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_conn()
    try:
        conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            user_id TEXT PRIMARY KEY,
            password TEXT NOT NULL,
            nickname TEXT,
            comment TEXT
        )
        """)
        conn.commit()
    finally:
        conn.close()


@app.on_event("startup")
def on_startup():
    init_db()


def db_get_user(user_id: str) -> Optional[sqlite3.Row]:
    conn = get_conn()
    try:
        cur = conn.execute(
            "SELECT user_id, password, nickname, comment FROM users WHERE user_id = ?", (user_id,))
        row = cur.fetchone()
        return row
    finally:
        conn.close()


def db_create_user(user_id: str, password: str):
    conn = get_conn()
    try:
        conn.execute(
            "INSERT INTO users (user_id, password, nickname, comment) VALUES (?, ?, ?, ?)",
            (user_id, password, user_id, None)
        )
        conn.commit()
    finally:
        conn.close()


def db_update_user(user_id: str, nickname: Optional[str], comment: Optional[str]):
    conn = get_conn()
    try:
        conn.execute(
            "UPDATE users SET nickname = ?, comment = ? WHERE user_id = ?",
            (nickname, comment, user_id)
        )
        conn.commit()
    finally:
        conn.close()


def db_delete_user(user_id: str):
    conn = get_conn()
    try:
        conn.execute("DELETE FROM users WHERE user_id = ?", (user_id,))
        conn.commit()
    finally:
        conn.close()

# ---------- Common ----------


def json400(msg: str, cause: str):
    return JSONResponse(status_code=400, content={"message": msg, "cause": cause})


def auth_user(creds: HTTPBasicCredentials | None = Depends(security)) -> str:
    # 失敗時は常に Authentication failed
    if creds is None or creds.username is None or creds.password is None:
        raise HTTPException(status_code=401, detail={
                            "message": "Authentication failed"})
    uid = creds.username
    pw = creds.password

    row = db_get_user(uid)
    if row is None or row["password"] != pw:
        raise HTTPException(status_code=401, detail={
                            "message": "Authentication failed"})
    return uid

# ---------- Endpoints ----------


@app.post("/signup")
async def signup(req: Request):
    try:
        data = await req.json()
    except Exception:
        return json400("Account creation failed", "Required user_id and password")

    uid = data.get("user_id")
    pw = data.get("password")

    # 必須
    if not uid or not pw:
        return json400("Account creation failed", "Required user_id and password")
    # 長さ
    if not (6 <= len(uid) <= 20) or not (8 <= len(pw) <= 20):
        return json400("Account creation failed", "Input length is incorrect")
    # 文字種
    if not USER_ID_RE.fullmatch(uid) or not PASSWORD_RE.fullmatch(pw):
        return json400("Account creation failed", "Incorrect character pattern")
    # 重複
    if db_get_user(uid) is not None:
        return json400("Account creation failed", "Already same user_id is used")

    db_create_user(uid, pw)
    return {
        "message": "Account successfully created",
        "user": {"user_id": uid, "nickname": uid}
    }


@app.get("/users/{user_id}")
def get_user(user_id: str, _: str = Depends(auth_user)):
    row = db_get_user(user_id)
    if row is None:
        raise HTTPException(status_code=404, detail={
                            "message": "No user found"})
    body = {
        "message": "User details by user_id",
        "user": {"user_id": row["user_id"], "nickname": row["nickname"]}
    }
    if row["comment"] is not None:
        body["user"]["comment"] = row["comment"]
    return JSONResponse(
        status_code=200,
        content=body,
        headers={"Cache-Control": "private, max-age=60"}
    )


class PatchBody(BaseModel):
    nickname: str | None = Field(default=None, max_length=30)
    comment: str | None = Field(default=None, max_length=100)


@app.patch("/users/{user_id}")
def patch_user(user_id: str, body: PatchBody, authed: str = Depends(auth_user)):
    # ★ 他人更新は即403（テスト期待に合わせる）
    if authed != user_id:
        raise HTTPException(status_code=403, detail={
                            "message": "No permission for update"})
    row = db_get_user(user_id)
    if row is None:
        raise HTTPException(status_code=404, detail={
                            "message": "No user found"})

    # いずれか必須（空文字はクリアOK）
    if body.nickname is None and body.comment is None:
        return JSONResponse(
            status_code=400,
            content={"message": "User updation failed",
                     "cause": "Required nickname or comment"}
        )

    def invalid(s: str | None) -> bool:
        if s is None:
            return False
        # 空文字はクリア許可。その他はASCII可視文字のみ
        return s != "" and not all(32 <= ord(c) <= 126 for c in s)

    if invalid(body.nickname) or invalid(body.comment):
        return JSONResponse(
            status_code=400,
            content={"message": "User updation failed",
                     "cause": "Invalid nickname or comment"}
        )

    new_nickname = None if body.nickname == "" else body.nickname if body.nickname is not None else row[
        "nickname"]
    new_comment = None if body.comment == "" else body.comment if body.comment is not None else row[
        "comment"]

    db_update_user(user_id, new_nickname, new_comment)

    return {
        "message": "User successfully updated",
        "user": {"nickname": new_nickname, "comment": new_comment}
    }


@app.post("/close")
def close_account(authed: str = Depends(auth_user)):
    db_delete_user(authed)
    return {"message": "Account and user successfully removed"}

# 統一エラーハンドラ


@app.exception_handler(HTTPException)
async def http_exc_handler(request: Request, exc: HTTPException):
    if isinstance(exc.detail, dict):
        return JSONResponse(status_code=exc.status_code, content=exc.detail)
    return JSONResponse(status_code=exc.status_code, content={"message": str(exc.detail)})
