from datetime import datetime, timedelta, timezone
from decimal import Decimal, ROUND_HALF_UP
from enum import Enum
import os
import uuid

from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import jwt, JWTError
from passlib.context import CryptContext
from pydantic import BaseModel, Field, EmailStr
from sqlalchemy import create_engine, String, Numeric, DateTime, ForeignKey, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker, Session


# ============================================================
# FG / Firaol Job API
# ============================================================

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./fg_job.db")
JWT_SECRET = os.getenv("FG_JWT_SECRET", "change-this-in-production")
JWT_ALG = "HS256"
ACCESS_MINUTES = int(os.getenv("FG_ACCESS_MINUTES", "30"))

if JWT_SECRET == "change-this-in-production":
    # Development is allowed, but production deployment should set FG_JWT_SECRET.
    pass

connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}

engine = create_engine(
    DATABASE_URL,
    connect_args=connect_args,
)

SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False,
)


class Base(DeclarativeBase):
    pass


class Role(str, Enum):
    WORKER = "worker"
    BUSINESS = "business"
    ADMIN = "admin"


class JobStatus(str, Enum):
    POSTED = "posted"
    APPLIED = "applied"
    HIRED = "hired"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    PAYMENT_PENDING = "payment_pending"
    PAID = "paid"


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(20))
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=lambda: datetime.now(timezone.utc)
    )


class Job(Base):
    __tablename__ = "jobs"

    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    business_id: Mapped[str] = mapped_column(ForeignKey("users.id"))
    title: Mapped[str] = mapped_column(String(200))
    description: Mapped[str] = mapped_column(String(5000))
    amount: Mapped[Decimal] = mapped_column(Numeric(18, 2))
    status: Mapped[str] = mapped_column(
        String(30), default=JobStatus.POSTED.value
    )
    worker_id: Mapped[str | None] = mapped_column(
        ForeignKey("users.id"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=lambda: datetime.now(timezone.utc)
    )


class Application(Base):
    __tablename__ = "applications"

    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    job_id: Mapped[str] = mapped_column(ForeignKey("jobs.id"))
    worker_id: Mapped[str] = mapped_column(ForeignKey("users.id"))
    status: Mapped[str] = mapped_column(String(30), default="applied")

    __table_args__ = (
        UniqueConstraint(
            "job_id",
            "worker_id",
            name="uq_job_worker",
        ),
    )


class Transaction(Base):
    __tablename__ = "transactions"

    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    job_id: Mapped[str] = mapped_column(ForeignKey("jobs.id"), unique=True)
    gross: Mapped[Decimal] = mapped_column(Numeric(18, 2))
    fg_fee: Mapped[Decimal] = mapped_column(Numeric(18, 2))
    worker_amount: Mapped[Decimal] = mapped_column(Numeric(18, 2))
    status: Mapped[str] = mapped_column(String(20), default="pending")
    idempotency_key: Mapped[str] = mapped_column(String(120), unique=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=lambda: datetime.now(timezone.utc)
    )


Base.metadata.create_all(engine)

app = FastAPI(
    title="FG Firaol Job",
    version="2.3.0",
    description="FG / Firaol Job marketplace API",
)

security = HTTPBearer()
pwd = CryptContext(schemes=["bcrypt"], deprecated="auto")


# ============================================================
# Database / helpers
# ============================================================

def db():
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


def money(value) -> Decimal:
    return Decimal(str(value)).quantize(
        Decimal("0.01"),
        rounding=ROUND_HALF_UP,
    )


def make_token(user: User) -> str:
    exp = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_MINUTES)

    payload = {
        "sub": user.id,
        "role": user.role,
        "exp": exp,
    }

    return jwt.encode(
        payload,
        JWT_SECRET,
        algorithm=JWT_ALG,
    )


def current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    session: Session = Depends(db),
) -> User:
    try:
        data = jwt.decode(
            credentials.credentials,
            JWT_SECRET,
            algorithms=[JWT_ALG],
        )

        user_id = data.get("sub")

        if not user_id:
            raise HTTPException(
                status_code=401,
                detail="Invalid token",
            )

    except (JWTError, KeyError):
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired token",
        )

    user = session.get(User, user_id)

    if not user:
        raise HTTPException(
            status_code=401,
            detail="User not found",
        )

    return user


def require_admin(user: User = Depends(current_user)) -> User:
    if user.role != Role.ADMIN.value:
        raise HTTPException(
            status_code=403,
            detail="Admin access required",
        )

    return user


# ============================================================
# Schemas
# ============================================================

class Register(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8)
    role: Role


class Login(BaseModel):
    email: EmailStr
    password: str


class JobIn(BaseModel):
    title: str = Field(min_length=2, max_length=200)
    description: str = Field(min_length=2, max_length=5000)
    amount: Decimal = Field(gt=0)


# ============================================================
# Basic
# ============================================================

@app.get("/")
def root():
    return {
        "service": "FG Firaol Job",
        "version": "2.3.0",
        "status": "online",
        "docs": "/docs",
    }


@app.get("/health")
def health():
    return {
        "ok": True,
        "service": "FG Firaol Job",
        "version": "2.3.0",
    }


# ============================================================
# Authentication
# ============================================================

@app.post("/auth/register")
def register(
    data: Register,
    session: Session = Depends(db),
):
    # Public registration may create only worker/business accounts.
    # Admin accounts must be created separately by the owner.
    if data.role == Role.ADMIN:
        raise HTTPException(
            status_code=403,
            detail="Admin registration is not allowed",
        )

    email = data.email.lower()

    existing = session.query(User).filter_by(email=email).first()

    if existing:
        raise HTTPException(
            status_code=409,
            detail="Email already registered",
        )

    user = User(
        id="usr_" + uuid.uuid4().hex[:12],
        email=email,
        password_hash=pwd.hash(data.password),
        role=data.role.value,
    )

    session.add(user)
    session.commit()
    session.refresh(user)

    return {
        "id": user.id,
        "email": user.email,
        "role": user.role,
    }


@app.post("/auth/login")
def login(
    data: Login,
    session: Session = Depends(db),
):
    user = (
        session.query(User)
        .filter_by(email=data.email.lower())
        .first()
    )

    if not user or not pwd.verify(
        data.password,
        user.password_hash,
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid credentials",
        )

    return {
        "access_token": make_token(user),
        "token_type": "bearer",
        "user_id": user.id,
        "role": user.role,
    }


# ============================================================
# Jobs
# ============================================================

@app.post("/jobs")
def create_job(
    data: JobIn,
    user: User = Depends(current_user),
    session: Session = Depends(db),
):
    if user.role not in (
        Role.BUSINESS.value,
        Role.ADMIN.value,
    ):
        raise HTTPException(
            status_code=403,
            detail="Business access required",
        )

    job = Job(
        id="job_" + uuid.uuid4().hex[:12],
        business_id=user.id,
        title=data.title,
        description=data.description,
        amount=money(data.amount),
        status=JobStatus.POSTED.value,
    )

    session.add(job)
    session.commit()
    session.refresh(job)

    return {
        "id": job.id,
        "title": job.title,
        "description": job.description,
        "amount": str(job.amount),
        "status": job.status,
    }


@app.get("/jobs")
def list_jobs(
    session: Session = Depends(db),
):
    jobs = (
        session.query(Job)
        .order_by(Job.created_at.desc())
        .all()
    )

    return [
        {
            "id": job.id,
            "title": job.title,
            "description": job.description,
            "amount": str(job.amount),
            "status": job.status,
        }
        for job in jobs
    ]


@app.get("/jobs/{job_id}")
def get_job(
    job_id: str,
    session: Session = Depends(db),
):
    job = session.get(Job, job_id)

    if not job:
        raise HTTPException(
            status_code=404,
            detail="Job not found",
        )

    return {
        "id": job.id,
        "business_id": job.business_id,
        "worker_id": job.worker_id,
        "title": job.title,
        "description": job.description,
        "amount": str(job.amount),
        "status": job.status,
    }


# ============================================================
# Applications
# ============================================================

@app.post("/jobs/{job_id}/apply")
def apply(
    job_id: str,
    user: User = Depends(current_user),
    session: Session = Depends(db),
):
    if user.role != Role.WORKER.value:
        raise HTTPException(
            status_code=403,
            detail="Worker access required",
        )

    job = session.get(Job, job_id)

    if not job:
        raise HTTPException(
            status_code=404,
            detail="Job not found",
        )

    if job.status not in (
        JobStatus.POSTED.value,
        JobStatus.APPLIED.value,
    ):
        raise HTTPException(
            status_code=409,
            detail="Job is no longer accepting applications",
        )

    existing = (
        session.query(Application)
        .filter_by(
            job_id=job_id,
            worker_id=user.id,
        )
        .first()
    )

    if existing:
        raise HTTPException(
            status_code=409,
            detail="Already applied",
        )

    application = Application(
        id="app_" + uuid.uuid4().hex[:12],
        job_id=job_id,
        worker_id=user.id,
        status="applied",
    )

    job.status = JobStatus.APPLIED.value

    session.add(application)
    session.commit()

    return {
        "id": application.id,
        "job_id": job_id,
        "status": application.status,
    }


@app.post("/applications/{application_id}/hire")
def hire(
    application_id: str,
    user: User = Depends(current_user),
    session: Session = Depends(db),
):
    application = session.get(Application, application_id)

    if not application:
        raise HTTPException(
            status_code=404,
            detail="Application not found",
        )

    job = session.get(Job, application.job_id)

    if not job:
        raise HTTPException(
            status_code=404,
            detail="Job not found",
        )

    if (
        user.role != Role.ADMIN.value
        and user.id != job.business_id
    ):
        raise HTTPException(
            status_code=403,
            detail="Not authorized",
        )

    if job.worker_id and job.worker_id != application.worker_id:
        raise HTTPException(
            status_code=409,
            detail="Job already has a worker",
        )

    application.status = "hired"
    job.status = JobStatus.HIRED.value
    job.worker_id = application.worker_id

    session.commit()

    return {
        "application_id": application.id,
        "job_id": job.id,
        "worker_id": job.worker_id,
        "status": job.status,
    }


# ============================================================
# Job progress / completion
# ============================================================

@app.post("/jobs/{job_id}/start")
def start_job(
    job_id: str,
    user: User = Depends(current_user),
    session: Session = Depends(db),
):
    job = session.get(Job, job_id)

    if not job:
        raise HTTPException(
            status_code=404,
            detail="Job not found",
        )

    if user.id not in (
        job.worker_id,
        job.business_id,
    ) and user.role != Role.ADMIN.value:
        raise HTTPException(
            status_code=403,
            detail="Not authorized",
        )

    if job.status != JobStatus.HIRED.value:
        raise HTTPException(
            status_code=409,
            detail="Job must be hired before starting",
        )

    job.status = JobStatus.IN_PROGRESS.value
    session.commit()

    return {
        "job_id": job.id,
        "status": job.status,
    }


@app.post("/jobs/{job_id}/complete")
def complete(
    job_id: str,
    user: User = Depends(current_user),
    session: Session = Depends(db),
):
    job = session.get(Job, job_id)

    if not job:
        raise HTTPException(
            status_code=404,
            detail="Job not found",
        )

    if user.id not in (
        job.worker_id,
        job.business_id,
    ) and user.role != Role.ADMIN.value:
        raise HTTPException(
            status_code=403,
            detail="Not authorized",
        )

    if job.status not in (
        JobStatus.HIRED.value,
        JobStatus.IN_PROGRESS.value,
    ):
        raise HTTPException(
            status_code=409,
            detail="Job must be hired or in progress",
        )

    existing = (
        session.query(Transaction)
        .filter_by(job_id=job_id)
        .first()
    )

    if existing:
        job.status = JobStatus.PAYMENT_PENDING.value
        session.commit()

        return {
            "job_status": job.status,
            "transaction_id": existing.id,
            "gross": str(existing.gross),
            "fg_fee": str(existing.fg_fee),
            "worker_amount": str(existing.worker_amount),
        }

    gross = money(job.amount)
    fee = money(gross * Decimal("0.10"))
    worker_amount = money(gross - fee)

    transaction = Transaction(
        id="tx_" + uuid.uuid4().hex[:12],
        job_id=job_id,
        gross=gross,
        fg_fee=fee,
        worker_amount=worker_amount,
        status="pending",
        idempotency_key="job-complete-" + job_id,
    )

    job.status = JobStatus.PAYMENT_PENDING.value

    session.add(transaction)
    session.commit()
    session.refresh(transaction)

    return {
        "job_status": job.status,
        "transaction_id": transaction.id,
        "gross": str(gross),
        "fg_fee": str(fee),
        "worker_amount": str(worker_amount),
    }


# ============================================================
# Payments
# ============================================================

@app.post("/payments/{transaction_id}/release")
def release(
    transaction_id: str,
    admin: User = Depends(require_admin),
    session: Session = Depends(db),
):
    transaction = session.get(
        Transaction,
        transaction_id,
    )

    if not transaction:
        raise HTTPException(
            status_code=404,
            detail="Transaction not found",
        )

    if transaction.status != "paid":
        transaction.status = "paid"

    job = session.get(
        Job,
        transaction.job_id,
    )

    if job:
        job.status = JobStatus.PAID.value

    session.commit()

    return {
        "transaction_id": transaction.id,
        "status": transaction.status,
        "fg_fee": str(transaction.fg_fee),
        "worker_amount": str(transaction.worker_amount),
    }


# ============================================================
# Admin finance
# ============================================================

@app.get("/admin/finance")
def finance(
    admin: User = Depends(require_admin),
    session: Session = Depends(db),
):
    paid = (
        session.query(Transaction)
        .filter_by(status="paid")
        .all()
    )

    gross_total = sum(
        (item.gross for item in paid),
        Decimal("0"),
    )

    commission_total = sum(
        (item.fg_fee for item in paid),
        Decimal("0"),
    )

    worker_total = sum(
        (item.worker_amount for item in paid),
        Decimal("0"),
    )

    return {
        "transactions": len(paid),
        "gross": str(money(gross_total)),
        "fg_commission": str(money(commission_total)),
        "worker_paid": str(money(worker_total)),
    }
