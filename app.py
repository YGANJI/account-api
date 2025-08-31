from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
import re

app = FastAPI()
security = HTTPBasic()

# 擬似DB（インメモリ）
# user_id -> {"password": "...", "nickname": "...", "comment": "..."}
USERS = {}

USER_ID_RE = re.compile(r"^[A-Za-z0-9]{6,20}$")
PASSWORD_RE = re.compile(r"^[A-Za-z0-9]{8,20}$")

def auth_user(creds: HTTPBasicCredentials = Depends(security)):
    uid = creds.username
    pw = creds.password or ""
    if uid not in USERS or USERS[uid]["password"] != pw:
        raise HTTPException(status_code=401, detail={"message": "Authentication failed"})
    return uid

def bad_request(cause: str):
    raise HTTPException(status_code=400, detail={"message": "Account creation failed", "cause": cause})

def bad_update(cause: str):
    raise HTTPException(status_code=400, detail={"message": "User updation failed", "cause": cause})

class SignupBody(BaseModel):
    user_id: str = Field(..., min_length=6, max_length=20)
    password: str = Field(..., min_length=8, max_length=20)

@app.post("/signup")
def signup(body: SignupBody):
    uid, pw = body.user_id, body.password
    # 必須チェックはPydanticで済む。追加で文字種チェック
    if not USER_ID_RE.fullmatch(uid) or not PASSWORD_RE.fullmatch(pw):
        cause = "Incorrect character pattern" if len(uid)>=6 and len(pw)>=8 else "Input length is incorrect"
        return JSONResponse(status_code=400, content={"message": "Account creation failed", "cause": cause})
    if uid in USERS:
        return JSONResponse(status_code=400, content={"message": "Account creation failed", "cause": "Already same user_id is used"})
    USERS[uid] = {"password": pw, "nickname": uid, "comment": None}
    return {
        "message": "Account successfully created",
        "user": {"user_id": uid, "nickname": uid}
    }

@app.get("/users/{user_id}")
def get_user(user_id: str, authed: str = Depends(auth_user)):
    if user_id not in USERS:
        raise HTTPException(status_code=404, detail={"message": "No user found"})
    user = USERS[user_id]
    body = {"message": "User details by user_id",
            "user": {"user_id": user_id,
                     "nickname": user.get("nickname")}}
    if user.get("comment") is not None:
        body["user"]["comment"] = user["comment"]
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
    if user_id not in USERS:
        raise HTTPException(status_code=404, detail={"message": "No user found"})
    if authed != user_id:
        raise HTTPException(status_code=403, detail={"message": "No permission for update"})

    # いずれか必須（空文字はクリアの意味）
    if body.nickname is None and body.comment is None:
        return JSONResponse(status_code=400, content={"message": "User updation failed", "cause": "Required nickname or comment"})

    # 不正文字（半角以外や制御文字）チェック
    def invalid(s: str | None) -> bool:
        if s is None: return False
        # 空文字はクリアOK。その他は ASCII 可視文字のみ
        return s != "" and not all(32 <= ord(c) <= 126 for c in s)

    if invalid(body.nickname) or invalid(body.comment):
        return JSONResponse(status_code=400, content={"message": "User updation failed", "cause": "Invalid nickname or comment"})

    u = USERS[user_id]
    if body.nickname is not None:
        u["nickname"] = None if body.nickname == "" else body.nickname
    if body.comment is not None:
        u["comment"] = None if body.comment == "" else body.comment

    return {
        "message": "User successfully updated",
        "user": {
            "nickname": u.get("nickname"),
            "comment": u.get("comment")
        }
    }

@app.post("/close")
def close_account(authed: str = Depends(auth_user)):
    # 認証に成功している＝authed が存在
    USERS.pop(authed, None)
    return {"message": "Account and user successfully removed"}

# 共通エラーハンドリング（detailにdictが入っている前提でそのまま返す）
@app.exception_handler(HTTPException)
async def http_exc_handler(request: Request, exc: HTTPException):
    if isinstance(exc.detail, dict):
        return JSONResponse(status_code=exc.status_code, content=exc.detail)
    return JSONResponse(status_code=exc.status_code, content={"message": str(exc.detail)})
