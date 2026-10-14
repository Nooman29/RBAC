"""Standard error format for the integration API: {"error": {"code", "message", "details?"}}."""

import logging
from typing import Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

logger = logging.getLogger(__name__)

_DEFAULT_CODES = {
    400: "bad_request",
    401: "unauthorized",
    403: "forbidden",
    404: "not_found",
    405: "method_not_allowed",
    409: "conflict",
    422: "validation_error",
    429: "rate_limited",
}


def api_error(status_code: int, code: str, message: str, headers: Optional[dict] = None) -> HTTPException:
    return HTTPException(status_code=status_code, detail={"code": code, "message": message}, headers=headers)


def _body(code: str, message: str, details=None) -> dict:
    error = {"code": code, "message": message}
    if details is not None:
        error["details"] = details
    return {"error": error}


def register_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(StarletteHTTPException)
    async def http_exception_handler(request: Request, exc: StarletteHTTPException):
        detail = exc.detail
        if isinstance(detail, dict) and "code" in detail:
            code, message = detail["code"], detail.get("message", "")
        else:
            code = _DEFAULT_CODES.get(exc.status_code, "error")
            message = str(detail)
        return JSONResponse(_body(code, message), status_code=exc.status_code, headers=getattr(exc, "headers", None))

    @app.exception_handler(RequestValidationError)
    async def validation_handler(request: Request, exc: RequestValidationError):
        details = [
            {"field": ".".join(str(p) for p in err["loc"] if p != "body"), "message": err["msg"]}
            for err in exc.errors()
        ]
        return JSONResponse(_body("validation_error", "Request validation failed.", details), status_code=422)

    @app.exception_handler(Exception)
    async def unhandled_handler(request: Request, exc: Exception):
        logger.exception("Unhandled error in integration API")
        return JSONResponse(_body("internal_error", "Unexpected server error."), status_code=500)