from datetime import datetime, timedelta, timezone
from decimal import Decimal, ROUND_HALF_UP
from enum import Enum
import os, uuid
from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import jwt, JWTError
from passlib.context import CryptContext
from pydantic import BaseModel, Field, EmailStr
from sqlalchemy import create_engine, String, Numeric, DateTime, ForeignKey, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker, Session

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./fg_job.db")
JWT_SECRET = os.getenv("FG_JWT_SECRET", "change-this-in-production")
JWT_ALG = "HS256"
ACCESS_MINUTES = int(os.getenv("FG_ACCESS_MINUTES", "30"))

connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, connect_args=connect_args)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)

class Base(DeclarativeBase): pass

class Role(str, Enum):
    WORKER="worker"; BUSINESS="business"; ADMIN="admin"
class JobStatus(str, Enum):
    POSTED="posted"; APPLIED="applied"; HIRED="hired"; IN_PROGRESS="in_progress"; COMPLETED="completed"; PAYMENT_PENDING="payment_pending"; PAID="paid"

class User(Base):
    __tablename__="users"
    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(20))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))

class Job(Base):
    __tablename__="jobs"
    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    business_id: Mapped[str] = mapped_column(ForeignKey("users.id"))
    title: Mapped[str] = mapped_column(String(200))
    description: Mapped[str] = mapped_column(String(5000))
    amount: Mapped[Decimal] = mapped_column(Numeric(18,2))
    status: Mapped[str] = mapped_column(String(30), default=JobStatus.POSTED.value)
    worker_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))

class Application(Base):
    __tablename__="applications"
    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    job_id: Mapped[str] = mapped_column(ForeignKey("jobs.id"))
    worker_id: Mapped[str] = mapped_column(ForeignKey("users.id"))
    status: Mapped[str] = mapped_column(String(30), default="applied")
    __table_args__=(UniqueConstraint("job_id","worker_id",name="uq_job_worker"),)

class Transaction(Base):
    __tablename__="transactions"
    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    job_id: Mapped[str] = mapped_column(ForeignKey("jobs.id"), unique=True)
    gross: Mapped[Decimal] = mapped_column(Numeric(18,2))
    fg_fee: Mapped[Decimal] = mapped_column(Numeric(18,2))
    worker_amount: Mapped[Decimal] = mapped_column(Numeric(18,2))
    status: Mapped[str] = mapped_column(String(20), default="pending")
    idempotency_key: Mapped[str] = mapped_column(String(120), unique=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))

Base.metadata.create_all(engine)

app=FastAPI(title="FG Firaol Job v2.2", version="2.2.0")
security=HTTPBearer()
pwd=CryptContext(schemes=["bcrypt"], deprecated="auto")

def db():
    s=SessionLocal()
    try: yield s
    finally: s.close()

def money(v): return Decimal(v).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)

def make_token(user: User):
    exp=datetime.now(timezone.utc)+timedelta(minutes=ACCESS_MINUTES)
    return jwt.encode({"sub":user.id,"role":user.role,"exp":exp}, JWT_SECRET, algorithm=JWT_ALG)

def current_user(creds: HTTPAuthorizationCredentials=Depends(security), s: Session=Depends(db)):
    try: data=jwt.decode(creds.credentials, JWT_SECRET, algorithms=[JWT_ALG]); uid=data["sub"]
    except (JWTError, KeyError): raise HTTPException(401,"Invalid or expired token")
    u=s.get(User,uid)
    if not u: raise HTTPException(401,"User not found")
    return u

class Register(BaseModel):
    email: EmailStr; password: str=Field(min_length=8); role: Role
class Login(BaseModel):
    email: EmailStr; password: str
class JobIn(BaseModel):
    title: str=Field(min_length=2,max_length=200); description: str=Field(min_length=2,max_length=5000); amount: Decimal=Field(gt=0)

@app.get("/health")
def health(): return {"ok":True,"service":"FG Firaol Job","version":"2.2.0"}

@app.post("/auth/register")
def register(x:Register,s:Session=Depends(db)):
    email=x.email.lower()
    if s.query(User).filter_by(email=email).first(): raise HTTPException(409,"Email already registered")
    u=User(id="usr_"+uuid.uuid4().hex[:12],email=email,password_hash=pwd.hash(x.password),role=x.role.value)
    s.add(u); s.commit(); s.refresh(u)
    return {"id":u.id,"email":u.email,"role":u.role}

@app.post("/auth/login")
def login(x:Login,s:Session=Depends(db)):
    u=s.query(User).filter_by(email=x.email.lower()).first()
    if not u or not pwd.verify(x.password,u.password_hash): raise HTTPException(401,"Invalid credentials")
    return {"access_token":make_token(u),"token_type":"bearer","user_id":u.id,"role":u.role}

@app.post("/jobs")
def create_job(x:JobIn,u:User=Depends(current_user),s:Session=Depends(db)):
    if u.role not in (Role.BUSINESS.value,Role.ADMIN.value): raise HTTPException(403,"Business access required")
    j=Job(id="job_"+uuid.uuid4().hex[:12],business_id=u.id,title=x.title,description=x.description,amount=money(x.amount),status=JobStatus.POSTED.value)
    s.add(j); s.commit(); s.refresh(j)
    return {"id":j.id,"title":j.title,"description":j.description,"amount":str(j.amount),"status":j.status}

@app.get("/jobs")
def list_jobs(s:Session=Depends(db)):
    return [{"id":j.id,"title":j.title,"description":j.description,"amount":str(j.amount),"status":j.status} for j in s.query(Job).all()]

@app.post("/jobs/{job_id}/apply")
def apply(job_id:str,u:User=Depends(current_user),s:Session=Depends(db)):
    if u.role != Role.WORKER.value: raise HTTPException(403,"Worker access required")
    j=s.get(Job,job_id)
    if not j: raise HTTPException(404,"Job not found")
    if s.query(Application).filter_by(job_id=job_id,worker_id=u.id).first(): raise HTTPException(409,"Already applied")
    a=Application(id="app_"+uuid.uuid4().hex[:12],job_id=job_id,worker_id=u.id,status="applied")
    j.status=JobStatus.APPLIED.value; s.add(a); s.commit(); return {"id":a.id,"job_id":job_id,"status":a.status}

@app.post("/applications/{application_id}/hire")
def hire(application_id:str,u:User=Depends(current_user),s:Session=Depends(db)):
    a=s.get(Application,application_id)
    if not a: raise HTTPException(404,"Application not found")
    j=s.get(Job,a.job_id)
    if u.role != Role.ADMIN.value and u.id != j.business_id: raise HTTPException(403,"Not authorized")
    a.status="hired"; j.status=JobStatus.HIRED.value; j.worker_id=a.worker_id; s.commit()
    return {"application_id":a.id,"job_id":j.id,"worker_id":j.worker_id,"status":j.status}

@app.post("/jobs/{job_id}/complete")
def complete(job_id:str,u:User=Depends(current_user),s:Session=Depends(db)):
    j=s.get(Job,job_id)
    if not j: raise HTTPException(404,"Job not found")
    if u.id not in (j.worker_id,j.business_id) and u.role != Role.ADMIN.value: raise HTTPException(403,"Not authorized")
    if j.status not in (JobStatus.HIRED.value,JobStatus.IN_PROGRESS.value): raise HTTPException(409,"Job must be hired or in progress")
    j.status=JobStatus.PAYMENT_PENDING.value
    existing=s.query(Transaction).filter_by(job_id=job_id).first()
    if existing: s.commit(); return {"job_status":j.status,"transaction_id":existing.id}
    gross=money(j.amount); fee=money(gross*Decimal("0.10")); worker=money(gross-fee)
    tx=Transaction(id="tx_"+uuid.uuid4().hex[:12],job_id=job_id,gross=gross,fg_fee=fee,worker_amount=worker,status="pending",idempotency_key="job-complete-"+job_id)
    s.add(tx); s.commit()
    return {"job_status":j.status,"transaction_id":tx.id,"gross":str(gross),"fg_fee":str(fee),"worker_amount":str(worker)}

@app.post("/payments/{tx_id}/release")
def release(tx_id:str,u:User=Depends(current_user),s:Session=Depends(db)):
    if u.role != Role.ADMIN.value: raise HTTPException(403,"Admin access required")
    tx=s.get(Transaction,tx_id)
    if not tx: raise HTTPException(404,"Transaction not found")
    if tx.status != "paid": tx.status="paid"
    j=s.get(Job,tx.job_id); j.status=JobStatus.PAID.value; s.commit()
    return {"transaction_id":tx.id,"status":tx.status,"fg_fee":str(tx.fg_fee),"worker_amount":str(tx.worker_amount)}

@app.get("/admin/finance")
def finance(u:User=Depends(current_user),s:Session=Depends(db)):
    if u.role != Role.ADMIN.value: raise HTTPException(403,"Admin access required")
    paid=s.query(Transaction).filter_by(status="paid").all()
    return {"transactions":len(paid),"gross":str(money(sum((x.gross for x in paid),Decimal("0")))),"fg_commission":str(money(sum((x.fg_fee for x in paid),Decimal("0")))),"worker_paid":str(money(sum((x.worker_amount for x in paid),Decimal("0"))))}
'''

cat > /mnt/data/fg_v22/requirements.txt <<'REQ'
fastapi>=0.115
uvicorn[standard]>=0.30
pydantic>=2.7
email-validator>=2.2
SQLAlchemy>=2.0
python-jose[cryptography]>=3.3
passlib[bcrypt]>=1.7
bcrypt>=4.1
alembic>=1.13
psycopg[binary]>=3.2
REQ

cat > /mnt/data/fg_v22/.env.example <<'ENV'
DATABASE_URL=sqlite:///./fg_job.db
# PostgreSQL example:
# DATABASE_URL=postgresql+psycopg://fg_user:CHANGE_ME@localhost:5432/fg_job
FG_JWT_SECRET=CHANGE_THIS_TO_A_LONG_RANDOM_SECRET
FG_ACCESS_MINUTES=30
ENV

cat > /mnt/data/fg_v22/README.md <<'MD'
# FG Firaol Job v2.2 — Database + JWT Foundation

v2.2 upgrades the v2.1 marketplace foundation with:
- SQLAlchemy database models
- SQLite development database
- PostgreSQL-ready DATABASE_URL
- JWT access tokens with expiry
- bcrypt password hashing
- role-based authorization
- unique job/worker application constraint
- database-backed jobs, applications and transactions
- 10% FG / 90% worker accounting
- idempotent job completion transaction creation

## Run

```bash
python -m venv .venv
pip install -r requirements.txt
uvicorn app.main:app --reload
```

API docs: `http://127.0.0.1:8000/docs`

## PostgreSQL

Set `DATABASE_URL` to a PostgreSQL connection string before starting the server.
Alembic migrations should be added before a production deployment; `create_all` is
kept here only to make the foundation immediately runnable.

## Security boundary

This is a production-oriented foundation, not a claim of production readiness or
100% security. Before real users/money: use a strong secret from a secrets manager,
PostgreSQL migrations, HTTPS, refresh-token/revocation strategy, rate limiting,
MFA, audit logging, backups, monitoring, vulnerability scanning, penetration testing,
and provider/legal/KYC/AML/privacy/tax controls.
MD

cat > /mnt/data/fg_v22/tests/test_commission.py <<'PY'
from decimal import Decimal

def test_commission_math():
    gross=Decimal('100.00')
    fee=(gross*Decimal('0.10')).quantize(Decimal('0.01'))
    assert fee == Decimal('10.00')
    assert gross-fee == Decimal('90.00')
