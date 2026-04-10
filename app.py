from __future__ import annotations

import asyncio
import json
import time
import uuid
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, File, HTTPException, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from config import INPUT_DIR, LOG_DIR, REPORT_DIR, ensure_runtime_dirs
from main import analyze_apk_async


@dataclass
class AnalyzeTask:
    task_id: str
    apk_name: str
    apk_path: str
    apk_stem: str
    status: str = "queued"
    started_at: Optional[float] = None
    ended_at: Optional[float] = None
    report_path: Optional[str] = None
    error: Optional[str] = None


class AnalyzeRequest(BaseModel):
    filename: Optional[str] = None


app = FastAPI(title="APK Vulnerability Scanner API", version="1.0.0")

# Dev-friendly CORS. If you have a fixed frontend origin, tighten this list.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

ensure_runtime_dirs()

_tasks: dict[str, AnalyzeTask] = {}
_task_lock = asyncio.Lock()
_current_task_id: Optional[str] = None
_latest_uploaded_filename: Optional[str] = None
_frontend_dist = Path(__file__).resolve().parent / "frontend" / "dist"


def _sanitize_filename(filename: str) -> str:
    cleaned = Path(filename or "").name
    if not cleaned:
        raise HTTPException(status_code=400, detail="Empty filename")
    return cleaned


def _resolve_apk_path(filename: str) -> Path:
    safe_name = _sanitize_filename(filename)
    apk_path = (INPUT_DIR / safe_name).resolve()
    if apk_path.parent != INPUT_DIR.resolve():
        raise HTTPException(status_code=400, detail="Invalid filename")
    if not apk_path.exists() or not apk_path.is_file():
        raise HTTPException(status_code=404, detail=f"APK not found: {safe_name}")
    return apk_path


def _task_snapshot(task: AnalyzeTask) -> dict:
    return asdict(task)


def _latest_completed_task() -> Optional[AnalyzeTask]:
    completed = [t for t in _tasks.values() if t.status == "completed" and t.ended_at is not None]
    if not completed:
        return None
    return max(completed, key=lambda t: t.ended_at or 0)


def _collect_task_logs(task: AnalyzeTask) -> list[Path]:
    candidates = [path for path in LOG_DIR.glob(f"*{task.apk_stem}*.log") if path.is_file()]
    if task.started_at is not None:
        threshold = task.started_at - 2
        filtered: list[Path] = []
        for path in candidates:
            try:
                if path.stat().st_mtime >= threshold:
                    filtered.append(path)
            except OSError:
                continue
        candidates = filtered

    return sorted(
        candidates,
        key=lambda p: (p.stat().st_mtime if p.exists() else 0, p.name),
    )


async def _run_analysis(task_id: str) -> None:
    global _current_task_id
    task = _tasks[task_id]
    task.status = "running"
    task.started_at = time.time()

    try:
        result = await analyze_apk_async(task.apk_path, print_summary=False)
        task.report_path = result.get("report_path")
        task.status = "completed"
    except Exception as exc:
        task.status = "failed"
        task.error = str(exc)
    finally:
        task.ended_at = time.time()
        if _current_task_id == task_id:
            _current_task_id = None


@app.get("/api/health")
async def health() -> dict:
    return {"ok": True, "current_task_id": _current_task_id}


@app.post("/api/upload")
async def upload_apk(file: UploadFile = File(...)) -> dict:
    global _latest_uploaded_filename

    filename = _sanitize_filename(file.filename or "")
    if Path(filename).suffix.lower() != ".apk":
        raise HTTPException(status_code=400, detail="Only .apk files are accepted")

    INPUT_DIR.mkdir(parents=True, exist_ok=True)
    destination = (INPUT_DIR / filename).resolve()
    if destination.parent != INPUT_DIR.resolve():
        raise HTTPException(status_code=400, detail="Invalid upload path")

    with destination.open("wb") as out:
        while True:
            chunk = await file.read(1024 * 1024)
            if not chunk:
                break
            out.write(chunk)

    await file.close()
    _latest_uploaded_filename = filename

    return {
        "message": "Upload successful",
        "filename": filename,
        "path": str(destination),
        "size": destination.stat().st_size,
    }


@app.post("/api/analyze")
async def analyze(request: AnalyzeRequest) -> dict:
    global _current_task_id

    requested_name = request.filename or _latest_uploaded_filename
    if not requested_name:
        raise HTTPException(status_code=400, detail="No APK specified and no uploaded APK found")

    apk_path = _resolve_apk_path(requested_name)

    async with _task_lock:
        if _current_task_id and _tasks.get(_current_task_id) and _tasks[_current_task_id].status in {"queued", "running"}:
            raise HTTPException(status_code=409, detail="Another analysis task is running")

        task_id = uuid.uuid4().hex
        task = AnalyzeTask(
            task_id=task_id,
            apk_name=apk_path.name,
            apk_path=str(apk_path),
            apk_stem=apk_path.stem,
        )
        _tasks[task_id] = task
        _current_task_id = task_id
        asyncio.create_task(_run_analysis(task_id))

    return {
        "message": "Analysis started",
        "task": _task_snapshot(task),
    }


@app.get("/api/task/{task_id}")
async def get_task(task_id: str) -> dict:
    task = _tasks.get(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    return {"task": _task_snapshot(task)}


@app.websocket("/api/logs")
async def websocket_logs(websocket: WebSocket, task_id: Optional[str] = None) -> None:
    await websocket.accept()

    try:
        task: Optional[AnalyzeTask]
        if task_id:
            task = _tasks.get(task_id)
            if not task:
                await websocket.send_json({"type": "error", "message": f"Task not found: {task_id}"})
                await websocket.close(code=1008)
                return
        else:
            if _current_task_id and _current_task_id in _tasks:
                task = _tasks[_current_task_id]
            else:
                task = _latest_completed_task()

        if not task:
            await websocket.send_json({"type": "error", "message": "No task available for log streaming"})
            await websocket.close(code=1008)
            return

        await websocket.send_json({
            "type": "meta",
            "task_id": task.task_id,
            "apk_name": task.apk_name,
            "status": task.status,
        })

        offsets: dict[str, int] = {}
        finished_idle_rounds = 0

        while True:
            had_new_data = False
            for log_file in _collect_task_logs(task):
                key = str(log_file)
                prev = offsets.get(key, 0)
                try:
                    current_size = log_file.stat().st_size
                except OSError:
                    continue

                if current_size < prev:
                    prev = 0

                if current_size == prev:
                    continue

                with log_file.open("r", encoding="utf-8", errors="replace") as handle:
                    handle.seek(prev)
                    chunk = handle.read()
                    offsets[key] = handle.tell()

                if chunk:
                    had_new_data = True
                    for line in chunk.splitlines():
                        await websocket.send_json(
                            {
                                "type": "log",
                                "task_id": task.task_id,
                                "file": log_file.name,
                                "message": line,
                            }
                        )

            if task.status in {"completed", "failed"}:
                if had_new_data:
                    finished_idle_rounds = 0
                else:
                    finished_idle_rounds += 1
                if finished_idle_rounds >= 2:
                    await websocket.send_json(
                        {
                            "type": "done",
                            "task_id": task.task_id,
                            "status": task.status,
                            "error": task.error,
                            "report_path": task.report_path,
                        }
                    )
                    break

            await asyncio.sleep(0.8)

    except WebSocketDisconnect:
        return


@app.get("/api/report")
async def get_report(task_id: Optional[str] = None, apk_name: Optional[str] = None) -> dict:
    report_path: Optional[Path] = None
    selected_task_id: Optional[str] = task_id

    if task_id:
        task = _tasks.get(task_id)
        if not task:
            raise HTTPException(status_code=404, detail="Task not found")
        if not task.report_path:
            raise HTTPException(status_code=404, detail="Report not ready")
        report_path = Path(task.report_path)
    elif apk_name:
        safe_name = _sanitize_filename(apk_name)
        report_path = REPORT_DIR / f"{safe_name}_vuln_report.json"
    else:
        latest = _latest_completed_task()
        if latest and latest.report_path:
            selected_task_id = latest.task_id
            report_path = Path(latest.report_path)

    if not report_path or not report_path.exists():
        raise HTTPException(status_code=404, detail="Report file not found")

    try:
        content = json.loads(report_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=500, detail=f"Invalid report JSON: {exc}") from exc

    return {
        "task_id": selected_task_id,
        "report_path": str(report_path),
        "report": content,
    }


if _frontend_dist.exists():
    app.mount(
        "/assets",
        StaticFiles(directory=_frontend_dist / "assets"),
        name="frontend-assets",
    )


@app.get("/{full_path:path}")
async def serve_frontend(full_path: str):
    if full_path.startswith("api"):
        return JSONResponse({"detail": "Not Found"}, status_code=404)

    if not _frontend_dist.exists():
        return JSONResponse(
            {"detail": "Frontend not built. Run `npm run build` in ./frontend first."},
            status_code=503,
        )

    target = (_frontend_dist / full_path).resolve()
    if (
        full_path
        and target.exists()
        and target.is_file()
        and target.parent == _frontend_dist
    ):
        return FileResponse(target)

    index_file = _frontend_dist / "index.html"
    if index_file.exists():
        return FileResponse(index_file)
    return JSONResponse({"detail": "Frontend entrypoint not found."}, status_code=503)


# Start with: uvicorn app:app --host 0.0.0.0 --port 8000 --reload
