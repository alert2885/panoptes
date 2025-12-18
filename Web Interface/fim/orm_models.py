"""SQLAlchemy ORM models"""
from sqlalchemy import Column, Integer, String, Text, Boolean, DateTime, JSON
from sqlalchemy.sql import func
from .db import Base


class Event(Base):
    """Events table model"""
    __tablename__ = "events"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    event_type = Column(String(50), nullable=False)
    file_path = Column(Text, nullable=False)
    timestamp = Column(String(50), nullable=False)
    endpoint = Column(String(255), nullable=False)
    hostname = Column(String(255), nullable=False)
    username = Column(String(255), nullable=False)
    hash_before = Column(Text, nullable=True)
    hash_after = Column(Text, nullable=True)
    state_hash = Column(Text, nullable=True)
    content_hash = Column(Text, nullable=True)
    file_size = Column(Integer, nullable=True)
    metadata_json = Column(JSON, nullable=True)
    alert_sent = Column(Boolean, default=False)
    
    def to_dict(self):
        """Convert model to dictionary"""
        return {
            "id": self.id,
            "event_type": self.event_type,
            "file_path": self.file_path,
            "timestamp": self.timestamp,
            "endpoint": self.endpoint,
            "hostname": self.hostname,
            "username": self.username,
            "hash_before": self.hash_before,
            "hash_after": self.hash_after,
            "state_hash": self.state_hash,
            "content_hash": self.content_hash,
            "file_size": self.file_size,
            "metadata_json": self.metadata_json,
            "alert_sent": self.alert_sent
        }


class FileClassification(Base):
    """File classification table model"""
    __tablename__ = "file_classification"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    file_path = Column(Text, nullable=False, unique=True)
    classification = Column(String(50), nullable=False)
    last_updated_timestamp = Column(String(50), nullable=False)
    endpoint = Column(String(255), nullable=True)
    hostname = Column(String(255), nullable=True)
    username = Column(String(255), nullable=True)
    
    def to_dict(self):
        """Convert model to dictionary"""
        return {
            "id": self.id,
            "file_path": self.file_path,
            "classification": self.classification,
            "last_updated_timestamp": self.last_updated_timestamp,
            "endpoint": self.endpoint,
            "hostname": self.hostname,
            "username": self.username
        }


class HashBaseline(Base):
    """Hash baseline table model"""
    __tablename__ = "hash_baseline"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    file_path = Column(Text, nullable=False, unique=True)
    hash_value = Column(Text, nullable=False)
    created_timestamp = Column(String(50), nullable=False)
    endpoint = Column(String(255), nullable=True)
    
    def to_dict(self):
        """Convert model to dictionary"""
        return {
            "id": self.id,
            "file_path": self.file_path,
            "hash_value": self.hash_value,
            "created_timestamp": self.created_timestamp,
            "endpoint": self.endpoint
        }


class AlertConfig(Base):
    """Alert configuration table model"""
    __tablename__ = "alert_config"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    config_name = Column(String(255), nullable=False, unique=True)
    config_value = Column(Text, nullable=True)
    enabled = Column(Boolean, default=True)
    updated_timestamp = Column(String(50), nullable=False)
    
    def to_dict(self):
        """Convert model to dictionary"""
        return {
            "id": self.id,
            "config_name": self.config_name,
            "config_value": self.config_value,
            "enabled": self.enabled,
            "updated_timestamp": self.updated_timestamp
        }


class AlertHistory(Base):
    """Alert history table model"""
    __tablename__ = "alert_history"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    event_id = Column(Integer, nullable=True)
    alert_type = Column(String(50), nullable=False)
    alert_message = Column(Text, nullable=False)
    sent_timestamp = Column(String(50), nullable=False)
    endpoint = Column(String(255), nullable=True)
    status = Column(String(50), nullable=True)
    
    def to_dict(self):
        """Convert model to dictionary"""
        return {
            "id": self.id,
            "event_id": self.event_id,
            "alert_type": self.alert_type,
            "alert_message": self.alert_message,
            "sent_timestamp": self.sent_timestamp,
            "endpoint": self.endpoint,
            "status": self.status
        }


