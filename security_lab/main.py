from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

from database import init_db
from routers import auth, lab_sql, lab_xss, lab_csrf, dashboard

app = FastAPI(title="Web Security Lab", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/static", StaticFiles(directory="security_lab/static"), name="static")
templates = Jinja2Templates(directory="security_lab/templates")

app.include_router(auth.router, prefix="/auth", tags=["auth"])
app.include_router(lab_sql.router, prefix="/lab/sql", tags=["sql-lab"])
app.include_router(lab_xss.router, prefix="/lab/xss", tags=["xss-lab"])
app.include_router(lab_csrf.router, prefix="/lab/csrf", tags=["csrf-lab"])
app.include_router(dashboard.router, prefix="/dashboard", tags=["dashboard"])


@app.on_event("startup")
async def startup():
    init_db()


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
