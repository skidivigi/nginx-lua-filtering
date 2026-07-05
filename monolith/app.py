from fastapi import FastAPI, Request, UploadFile, File
from fastapi.responses import JSONResponse
from typing import Optional

app = FastAPI()


@app.get("/")
def root():
    return {
        "service": "legacy-monolith",
        "status": "ok",
    }


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
async def catch_all(
    path: str,
    request: Request,
    file: Optional[UploadFile] = File(default=None),
):
    if file is not None:
        content = await file.read()

        return {
            "status": "accepted_by_monolith",
            "path": "/" + path,
            "filename": file.filename,
            "content_type": file.content_type,
            "size": len(content),
        }

    body = await request.body()

    return JSONResponse(
        {
            "status": "accepted_by_monolith",
            "path": "/" + path,
            "method": request.method,
            "body_size": len(body),
            "content_type": request.headers.get("content-type"),
        }
    )