"""Database models and data access layer using SQLAlchemy"""
from typing import Optional, List, Dict, Any
from sqlalchemy import func, or_, and_
from sqlalchemy.orm import Session
from sqlalchemy.exc import OperationalError, SQLAlchemyError
from .db import SessionLocal, init_db
from .orm_models import Event, FileClassification, HashBaseline, AlertConfig, AlertHistory


def get_session() -> Session:
    """Get a database session"""
    return SessionLocal()


def init_database() -> bool:
    """Initialize the database and create tables
    
    Returns:
        bool: True if initialization succeeded, False otherwise
    """
    from .db import init_db
    return init_db()


def insert_event(data: Dict[str, Any]) -> int:
    """Insert a single event into the database
    
    Args:
        data: Dictionary with event data including all fields
    
    Returns:
        The ID of the inserted event, or 0 if insertion failed
    """
    db = get_session()
    try:
        event = Event(
            event_type=data.get("event_type"),
            file_path=data.get("file_path"),
            timestamp=data.get("timestamp"),
            endpoint=data.get("endpoint"),
            hostname=data.get("hostname"),
            username=data.get("username"),
            hash_before=data.get("hash_before"),
            hash_after=data.get("hash_after"),
            state_hash=data.get("state_hash"),
            content_hash=data.get("content_hash"),
            file_size=data.get("file_size"),
            metadata_json=data.get("metadata_json"),
            alert_sent=data.get("alert_sent", False)
        )
        db.add(event)
        db.commit()
        db.refresh(event)
        return event.id
    except (OperationalError, SQLAlchemyError) as e:
        print(f"[DB] Error inserting event: {e}")
        db.rollback()
        return 0
    finally:
        db.close()


def get_latest_hash(file_path: str) -> Optional[str]:
    """Get the most recent hash_after for a given file path
    
    Args:
        file_path: Path to the file
    
    Returns:
        The most recent hash_after value, or None if not found
    """
    db = get_session()
    try:
        event = db.query(Event).filter(
            Event.file_path == file_path,
            Event.hash_after.isnot(None)
        ).order_by(Event.timestamp.desc()).first()
        
        return event.hash_after if event else None
    except (OperationalError, SQLAlchemyError):
        return None
    finally:
        db.close()


def get_latest_events(limit: int = 100, event_type: Optional[str] = None) -> List[Dict[str, Any]]:
    """Get the latest events from the database
    
    Args:
        limit: Maximum number of events to return
        event_type: Optional filter by event type (created/modified/deleted)
    
    Returns:
        List of event dictionaries ordered by timestamp (newest first)
    """
    db = get_session()
    try:
        query = db.query(Event)
        
        if event_type and event_type != "all":
            query = query.filter(Event.event_type == event_type)
        
        events = query.order_by(Event.timestamp.desc()).limit(limit).all()
        
        return [event.to_dict() for event in events]
    except (OperationalError, SQLAlchemyError) as e:
        print(f"[DB] Query error in get_latest_events: {e}")
        return []
    finally:
        db.close()


def get_latest_events_filtered(
    limit: int = 100,
    event_types: Optional[List[str]] = None,
    search_query: Optional[str] = None,
    search_columns: Optional[List[str]] = None
) -> List[Dict[str, Any]]:
    """Get the latest events with advanced filtering
    
    Args:
        limit: Maximum number of events to return
        event_types: Optional list of event types to filter (created/modified/deleted)
        search_query: Optional search query string
        search_columns: Optional list of columns to search in (if None, searches all)
    
    Returns:
        List of event dictionaries ordered by timestamp (newest first)
    """
    db = get_session()
    try:
        query = db.query(Event)
        
        # Filter by event types
        if event_types and len(event_types) > 0:
            query = query.filter(Event.event_type.in_(event_types))
        
        # Search query
        if search_query and search_query.strip():
            search_term = f"%{search_query.strip()}%"
            conditions = []
            
            if search_columns and len(search_columns) > 0:
                # Search in specific columns
                column_map = {
                    "timestamp": Event.timestamp,
                    "event_type": Event.event_type,
                    "file_path": Event.file_path,
                    "endpoint": Event.endpoint,
                    "hostname": Event.hostname,
                    "username": Event.username
                }
                
                for col in search_columns:
                    if col in column_map:
                        conditions.append(column_map[col].like(search_term))
            else:
                # Search in all columns
                conditions = [
                    Event.timestamp.like(search_term),
                    Event.event_type.like(search_term),
                    Event.file_path.like(search_term),
                    Event.endpoint.like(search_term),
                    Event.hostname.like(search_term),
                    Event.username.like(search_term)
                ]
            
            if conditions:
                query = query.filter(or_(*conditions))
        
        events = query.order_by(Event.timestamp.desc()).limit(limit).all()
        
        return [event.to_dict() for event in events]
    except (OperationalError, SQLAlchemyError) as e:
        print(f"[DB] Query error in get_latest_events_filtered: {e}")
        return []
    finally:
        db.close()


def get_distinct_file_paths(endpoints: Optional[List[str]] = None) -> List[Dict[str, Any]]:
    """Get distinct file paths with their latest event information
    
    Args:
        endpoints: Optional list of endpoints to filter by
    
    Returns:
        List of dictionaries with file_path and latest event info
    """
    db = get_session()
    try:
        # Subquery to get max timestamp per file_path
        subquery = db.query(
            Event.file_path,
            func.max(Event.timestamp).label('max_timestamp')
        ).group_by(Event.file_path).subquery()
        
        # Main query to get latest event for each file_path
        query = db.query(Event).join(
            subquery,
            and_(
                Event.file_path == subquery.c.file_path,
                Event.timestamp == subquery.c.max_timestamp
            )
        )
        
        if endpoints and len(endpoints) > 0:
            query = query.filter(Event.endpoint.in_(endpoints))
        
        events = query.order_by(Event.timestamp.desc()).all()
        
        files = []
        seen_paths = set()
        for event in events:
            if event.file_path not in seen_paths:
                files.append({
                    "file_path": event.file_path,
                    "last_timestamp": event.timestamp,
                    "endpoint": event.endpoint,
                    "hostname": event.hostname,
                    "username": event.username
                })
                seen_paths.add(event.file_path)
        
        return files
    except (OperationalError, SQLAlchemyError) as e:
        print(f"[DB] Query error in get_distinct_file_paths: {e}")
        return []
    finally:
        db.close()


def get_file_classification(file_path: str) -> Optional[Dict[str, Any]]:
    """Get classification for a specific file path
    
    Args:
        file_path: Path to the file
    
    Returns:
        Classification dictionary or None if not found
    """
    db = get_session()
    try:
        classification = db.query(FileClassification).filter(
            FileClassification.file_path == file_path
        ).first()
        
        return classification.to_dict() if classification else None
    except (OperationalError, SQLAlchemyError):
        return None
    finally:
        db.close()


def upsert_file_classification(
    file_path: str,
    classification: str,
    endpoint: Optional[str] = None,
    hostname: Optional[str] = None,
    username: Optional[str] = None
) -> int:
    """Insert or update file classification
    
    Args:
        file_path: Path to the file
        classification: Classification level (Top Secret, Secret, Confidential, Unclassified)
        endpoint: Optional endpoint
        hostname: Optional hostname
        username: Optional username
    
    Returns:
        The ID of the inserted/updated record, or 0 if operation failed
    """
    from datetime import datetime
    
    db = get_session()
    try:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        existing = db.query(FileClassification).filter(
            FileClassification.file_path == file_path
        ).first()
        
        if existing:
            existing.classification = classification
            existing.last_updated_timestamp = timestamp
            existing.endpoint = endpoint
            existing.hostname = hostname
            existing.username = username
            record_id = existing.id
        else:
            new_classification = FileClassification(
                file_path=file_path,
                classification=classification,
                last_updated_timestamp=timestamp,
                endpoint=endpoint,
                hostname=hostname,
                username=username
            )
            db.add(new_classification)
            record_id = new_classification.id
        
        db.commit()
        return record_id
    except (OperationalError, SQLAlchemyError) as e:
        print(f"[DB] Error upserting classification: {e}")
        db.rollback()
        return 0
    finally:
        db.close()


def get_all_classifications(endpoints: Optional[List[str]] = None) -> List[Dict[str, Any]]:
    """Get all file classifications, optionally filtered by endpoints
    
    Args:
        endpoints: Optional list of endpoints to filter by
    
    Returns:
        List of classification dictionaries
    """
    db = get_session()
    try:
        query = db.query(FileClassification)
        
        if endpoints and len(endpoints) > 0:
            query = query.filter(FileClassification.endpoint.in_(endpoints))
        
        classifications = query.order_by(FileClassification.last_updated_timestamp.desc()).all()
        
        return [cls.to_dict() for cls in classifications]
    except (OperationalError, SQLAlchemyError) as e:
        print(f"[DB] Query error in get_all_classifications: {e}")
        return []
    finally:
        db.close()


def get_distinct_endpoints() -> List[str]:
    """Get list of distinct endpoints from events table
    
    Returns:
        List of endpoint strings
    """
    db = get_session()
    try:
        endpoints = db.query(Event.endpoint).distinct().order_by(Event.endpoint).all()
        return [ep[0] for ep in endpoints if ep[0]]
    except (OperationalError, SQLAlchemyError) as e:
        print(f"[DB] Query error in get_distinct_endpoints: {e}")
        return []
    finally:
        db.close()


def get_event_counts() -> Dict[str, int]:
    """Get counts of events by type
    
    Returns:
        Dictionary with event counts: {'all': total, 'created': count, 'modified': count, 'deleted': count}
    """
    db = get_session()
    try:
        # Get total count
        total = db.query(func.count(Event.id)).scalar()
        
        # Get counts by type
        counts_by_type = db.query(
            Event.event_type,
            func.count(Event.id).label('count')
        ).group_by(Event.event_type).all()
        
        counts = {
            'all': total or 0,
            'created': 0,
            'modified': 0,
            'deleted': 0
        }
        
        for event_type, count in counts_by_type:
            event_type_lower = event_type.lower() if event_type else None
            if event_type_lower in counts:
                counts[event_type_lower] = count
        
        return counts
    except (OperationalError, SQLAlchemyError) as e:
        print(f"[DB] Query error in get_event_counts: {e}")
        return {
            'all': 0,
            'created': 0,
            'modified': 0,
            'deleted': 0
        }
    finally:
        db.close()
