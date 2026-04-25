from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

from security_lab.database import init_db
from security_lab.routers import admin, auth, blog, lab_sql, lab_xss, lab_csrf, dashboard

BASE_DIR = Path(__file__).resolve().parent

app = FastAPI(title="Web Security Lab", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

app.include_router(auth.router, prefix="/auth", tags=["auth"])
app.include_router(lab_sql.router, prefix="/lab/sql", tags=["sql-lab"])
app.include_router(lab_xss.router, prefix="/lab/xss", tags=["xss-lab"])
app.include_router(lab_csrf.router, prefix="/lab/csrf", tags=["csrf-lab"])
app.include_router(dashboard.router, prefix="/dashboard", tags=["dashboard"])
app.include_router(blog.router, prefix="/blog", tags=["blog"])
app.include_router(admin.router, prefix="/admin/api", tags=["admin"])


@app.on_event("startup")
async def startup():
    init_db()


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@app.get("/admin", response_class=HTMLResponse)
async def admin_page(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@app.get("/security-lab", response_class=HTMLResponse)
async def security_lab_page(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@app.get("/blog", response_class=HTMLResponse)
async def blog_page(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@app.get("/chat", response_class=HTMLResponse)
async def chat_page(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@app.get("/about", response_class=HTMLResponse)
async def about_page(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@app.get("/profile", response_class=HTMLResponse)
async def profile_page(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@app.get("/detail", response_class=HTMLResponse)
async def detail_page(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


if __name__ == "__main__":
    uvicorn.run("security_lab.main:app", host="0.0.0.0", port=8000, reload=True)
