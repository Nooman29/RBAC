"""
Demo module: School Meal Attendance.

This module has NO accounts and NO permission rules of its own. It
  - signs users in by relaying to the central RBAC service (password, then the emailed code),
  - asks the central service before every action (POST /api/v1/authz/check, through the shared client),
  - and reports what users did (POST /api/v1/events), which feeds anomaly detection and the audit trail.

Student and school ids belong to THIS module; the RBAC service only compares them.
Environment: DSFS_AUTH_URL, DSFS_CLIENT_ID, DSFS_CLIENT_SECRET.
"""

import os
from typing import Dict

import requests
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse
from pydantic import BaseModel

from dsfs_auth_client import DsfsAuthClient, DsfsAuthError, require_permission

AUTH_URL = os.environ.get("DSFS_AUTH_URL", "http://host.docker.internal:8000").rstrip("/")
auth = DsfsAuthClient(AUTH_URL, os.environ["DSFS_CLIENT_ID"], os.environ["DSFS_CLIENT_SECRET"])

app = FastAPI(title="Demo: School Meal Attendance module")

STUDENTS = {
    "SCH-1": [
        {"student_id": "STU-1001", "name": "Amina Otieno"},
        {"student_id": "STU-1002", "name": "Brian Mwangi"},
        {"student_id": "STU-1003", "name": "Cynthia Wanjiru"},
    ],
    "SCH-2": [
        {"student_id": "STU-2001", "name": "David Kiptoo"},
        {"student_id": "STU-2002", "name": "Esther Achieng"},
    ],
}
SCHOOL_OF = {s["student_id"]: school for school, students in STUDENTS.items() for s in students}
NAME_OF = {s["student_id"]: s["name"] for students in STUDENTS.values() for s in students}
ATTENDANCE: Dict[str, bool] = {"STU-1001": True, "STU-1002": False, "STU-2001": True}


class LoginIn(BaseModel):
    username: str
    password: str


class CodeRequestIn(BaseModel):
    pending_token: str


class VerifyIn(BaseModel):
    pending_token: str
    code: str


class MarkIn(BaseModel):
    student_id: str
    present: bool


def _token(request: Request) -> str:
    header = request.headers.get("authorization", "")
    if not header.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing bearer token")
    return header[7:].strip()


def _relay(method: str, path: str, **kwargs):
    """Forward a sign-in step to the central service and pass its answer (or its error) back."""
    try:
        resp = requests.request(method, f"{AUTH_URL}{path}", timeout=20, **kwargs)
    except requests.RequestException as exc:
        raise HTTPException(status_code=503, detail=f"Central service unreachable: {exc}")
    try:
        body = resp.json()
    except ValueError:
        body = {"detail": resp.text}
    if resp.status_code >= 400:
        detail = body.get("detail") if isinstance(body, dict) else None
        raise HTTPException(status_code=resp.status_code, detail=detail or "Request failed")
    return body


# ---- sign-in (relayed) ------------------------------------------------------------------------------

@app.post("/api/login")
def login(payload: LoginIn):
    return _relay("POST", "/api/auth/login", data={"username": payload.username, "password": payload.password})


@app.post("/api/send-code")
def send_code(payload: CodeRequestIn):
    return _relay("POST", "/api/auth/request-otp", json={"pending_token": payload.pending_token})


@app.post("/api/verify")
def verify(payload: VerifyIn):
    return _relay("POST", "/api/auth/verify-otp", params={"code": payload.code},
                  json={"pending_token": payload.pending_token})


@app.post("/api/logout")
def logout(request: Request):
    return _relay("POST", "/api/auth/logout", headers={"Authorization": f"Bearer {_token(request)}"})


@app.get("/api/me")
def me(request: Request):
    try:
        info = auth.introspect(_token(request))
    except DsfsAuthError as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    if not info.get("active"):
        raise HTTPException(status_code=401, detail=f"Session is not active ({info.get('reason')})")
    return {
        "username": info["username"],
        "roles": [r["role_name"] for r in info["roles"]],
        "school_id": info.get("school_id"),
    }


# ---- attendance: every action is decided by the central service -------------------------------------

def _school_context(request: Request) -> dict:
    return {"school_id": request.path_params["school_id"]}


def _child_context(request: Request) -> dict:
    student_id = request.path_params["student_id"]
    return {"school_id": SCHOOL_OF.get(student_id), "student_id": student_id}


@app.get("/api/schools/{school_id}/attendance")
def school_attendance(
    school_id: str,
    decision=Depends(require_permission(auth, "attendance", "read", context_getter=_school_context)),
):
    students = STUDENTS.get(school_id)
    if students is None:
        raise HTTPException(status_code=404, detail="Unknown school")
    return {
        "school_id": school_id,
        "decision": decision,
        "students": [{**s, "present": ATTENDANCE.get(s["student_id"])} for s in students],
    }


@app.post("/api/schools/{school_id}/attendance")
def mark_attendance(
    school_id: str,
    payload: MarkIn,
    request: Request,
    decision=Depends(require_permission(auth, "attendance", "write", context_getter=_school_context)),
):
    if SCHOOL_OF.get(payload.student_id) != school_id:
        raise HTTPException(status_code=404, detail="That student is not in this school")
    ATTENDANCE[payload.student_id] = payload.present

    # Tell the central service what happened: it joins the user's session for anomaly detection and the audit trail.
    reported = auth.report_events(_token(request), [{
        "resource": "attendance",
        "action": "write",
        "entity_ref": f"{payload.student_id}:{'present' if payload.present else 'absent'}",
    }])
    return {"decision": decision, "recorded": True, "reported_to_rbac": reported}


@app.get("/api/children/{student_id}/attendance")
def child_attendance(
    student_id: str,
    decision=Depends(require_permission(auth, "attendance", "read", context_getter=_child_context)),
):
    if student_id not in SCHOOL_OF:
        raise HTTPException(status_code=404, detail="Unknown student")
    return {
        "decision": decision,
        "student_id": student_id,
        "name": NAME_OF[student_id],
        "present": ATTENDANCE.get(student_id),
    }


@app.get("/")
def index():
    return FileResponse("static/index.html")