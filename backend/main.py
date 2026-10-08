from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .database import (
    initialize_database,
    insert_log,
    get_all_logs,
    get_statistics
)

from .models import SecurityLog


app = FastAPI(
    title="Autonomous API Detection",
    description="Member 3 - Database and Monitoring Backend",
    version="1.0.0"
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)


initialize_database()


@app.get("/")
def home():
    return {
        "message": "Autonomous API Detection",
        "module": "Member 3 - Database",
        "status": "running"
    }


@app.post("/api/log")
def create_security_log(log: SecurityLog):
    log_id = insert_log(
        log.model_dump()
    )

    return {
        "message": "Security event stored successfully",
        "id": log_id
    }


@app.get("/api/logs")
def get_logs():
    return get_all_logs()


@app.get("/api/statistics")
def statistics():
    return get_statistics()