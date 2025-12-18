"""Database connection and session management"""
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from .config import DATABASE_URL

# Create engine
engine = create_engine(DATABASE_URL, pool_pre_ping=True)

# Create session factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Base class for declarative models
Base = declarative_base()


def get_db():
    """Get database session"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    """Initialize database tables
    
    Returns:
        bool: True if initialization succeeded, False otherwise
    """
    from sqlalchemy.exc import OperationalError, SQLAlchemyError
    from .orm_models import Event, FileClassification, HashBaseline, AlertConfig, AlertHistory
    
    try:
        Base.metadata.create_all(bind=engine)
        print("[DB] Database tables initialized successfully")
        return True
    except OperationalError as e:
        print(f"[DB] WARNING: Could not connect to database at {DATABASE_URL.split('@')[1] if '@' in DATABASE_URL else 'configured address'}")
        print(f"[DB] Error details: {str(e).split('(')[0] if '(' in str(e) else str(e)}")
        print("[DB] The application will start, but database operations will fail until connection is established.")
        return False
    except SQLAlchemyError as e:
        print(f"[DB] ERROR: Database error during initialization: {e}")
        return False
    except Exception as e:
        print(f"[DB] ERROR: Unexpected error during database initialization: {e}")
        return False

