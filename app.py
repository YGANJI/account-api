from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
import re

app = FastAPI()

# ★ auto_error=False にして自前で401を制御
security = HTTPBasic(auto_error=False)

# 擬似DB（インメモリ）
USERS = {}

USER_ID_RE = re.compile(r"^[A-Za-z0-9]{6,20}$")
PASSWORD_RE = re.compile(r"^[A-Za-z0-9]{8,20}$")


def auth_user(creds: HTTPBasicCredentials | None = Depends(security)) -> str:
    """Basic認証。失敗時は 'Authentication failed' を返す"""
    if creds is None or creds.username is None or creds.password is None:
        raise HTTPException(status_code=401, detail={
                            "message": "Authentication failed"})
    uid = creds.username
    pw = creds.password
    if uid not in USERS or USERS[uid]["password"] != pw:
        raise HTTPException(status_code=401, detail={
                            "message": "Authentication failed"})
    return uid


def json400(msg: str, cause: str):
    return JSONResponse(status_code=400, content={"message": msg, "cause": cause})

# ------------------------
# POST /signup
# ------------------------


@app.post("/signup")
async def signup(req: Request):
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

    if uid in USERS:
        return json400("Account creation failed", "Already same user_id is used")

    USERS[uid] = {"password": pw, "nickname": uid, "comment": None}
    return {
        "message": "Account successfully created",
        "user": {"user_id": uid, "nickname": uid}
    }

# ------------------------
# GET /users/{user_id}
# ------------------------


@app.get("/users/{user_id}")
def get_user(user_id: str, _: str = Depends(auth_user)):
    if user_id not in USERS:
        raise HTTPException(status_code=404, detail={
                            "message": "No user found"})
    user = USERS[user_id]
    body = {
        "message": "User details by user_id",
        "user": {"user_id": user_id, "nickname": user.get("nickname")}
    }
    if user.get("comment") is not None:
        body["user"]["comment"] = user["comment"]

    return JSONResponse(
        status_code=200,
        content=body,
        headers={"Cache-Control": "private, max-age=60"}
    )

# ------------------------
# PATCH /users/{user_id}
# ------------------------


class PatchBody(BaseModel):
    nickname: str | None = Field(default=None, max_length=30)
    comment: str | None = Field(default=None, max_length=100)


@app.patch("/users/{user_id}")
def patch_user(user_id: str, body: PatchBody, authed: str = Depends(auth_user)):
    # ★ 本人チェックを先に（403を優先）
    if authed != user_id:
        raise HTTPException(status_code=403, detail={
                            "message": "No permission for update"})
    if user_id not in USERS:
        raise HTTPException(status_code=404, detail={
                            "message": "No user found"})

    if body.nickname is None and body.comment is None:
        return JSONResponse(
            status_code=400,
            content={"message": "User updation failed",
                     "cause": "Required nickname or comment"}
        )

    def invalid(s: str | None) -> bool:
        if s is None:
            return False
        return s != "" and not all(32 <= ord(c) <= 126 for c in s)

    if invalid(body.nickname) or invalid(body.comment):
        return JSONResponse(
            status_code=400,
            content={"message": "User updation failed",
                     "cause": "Invalid nickname or comment"}
        )

    u = USERS[user_id]
    if body.nickname is not None:
        u["nickname"] = None if body.nickname == "" else body.nickname
    if body.comment is not None:
        u["comment"] = None if body.comment == "" else body.comment

    return {
        "message": "User successfully updated",
        "user": {"nickname": u.get("nickname"), "comment": u.get("comment")}
    }

# ------------------------
# POST /close
# ------------------------


@app.post("/close")
def close_account(authed: str = Depends(auth_user)):
    USERS.pop(authed, None)
    return {"message": "Account and user successfully removed"}

# ------------------------
# エラーハンドラ
# ------------------------


@app.exception_handler(HTTPException)
async def http_exc_handler(request: Request, exc: HTTPException):
    if isinstance(exc.detail, dict):
        return JSONResponse(status_code=exc.status_code, content=exc.detail)
    return JSONResponse(status_code=exc.status_code, content={"message": str(exc.detail)})
