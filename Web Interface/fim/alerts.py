"""Console alert functions"""
from datetime import datetime


def print_alert(event_type: str, file_path: str, endpoint: str, 
                hostname: str, username: str, timestamp: str = None) -> None:
    """Print a console alert for a file system event
    
    Args:
        event_type: Type of event (created/modified/deleted)
        file_path: Path to the file
        endpoint: Endpoint identifier
        hostname: Hostname
        username: Username
        timestamp: Optional timestamp string (defaults to current time)
    """
    if timestamp is None:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    alert_type = event_type.upper()
    
    print(f"[ALERT] {timestamp} {alert_type} {file_path} "
          f"endpoint={endpoint} hostname={hostname} user={username}")






