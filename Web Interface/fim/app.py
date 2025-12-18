"""Flask web dashboard"""
import os
from flask import Flask, render_template, request, redirect, url_for, jsonify
from .models import (
    get_latest_events,
    get_latest_events_filtered,
    get_distinct_file_paths,
    get_file_classification,
    upsert_file_classification,
    get_all_classifications,
    get_distinct_endpoints,
    get_event_counts
)
from .config import FLASK_HOST, FLASK_PORT

# Get the root directory (parent of fim package)
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEMPLATE_DIR = os.path.join(ROOT_DIR, "templates")
STATIC_DIR = os.path.join(ROOT_DIR, "static")

app = Flask(__name__, template_folder=TEMPLATE_DIR, static_folder=STATIC_DIR)


@app.route("/")
def index():
    """Main dashboard page with advanced filtering"""
    # Get search query
    search_query = request.args.get("search", "").strip()
    
    # Get event types (can be multiple checkboxes)
    event_types_param = request.args.get("types", "")
    if event_types_param:
        event_types = [t.strip() for t in event_types_param.split(",") if t.strip()]
        # Remove "all" if other types are selected
        if "all" in event_types and len(event_types) > 1:
            event_types.remove("all")
        elif "all" in event_types:
            event_types = None
    else:
        event_types = None
    
    # Get search columns
    search_columns_param = request.args.get("columns", "")
    if search_columns_param:
        search_columns = [c.strip() for c in search_columns_param.split(",") if c.strip()]
        if "all" in search_columns:
            search_columns = None  # Search all columns
    else:
        search_columns = None
    
    # Fetch events with filtering
    if search_query or (event_types and len(event_types) > 0):
        events = get_latest_events_filtered(
            limit=100,
            event_types=event_types,
            search_query=search_query if search_query else None,
            search_columns=search_columns
        )
    else:
        # Legacy support - check for single type parameter
        event_type = request.args.get("type", "all")
        valid_types = ["all", "created", "modified", "deleted"]
        if event_type not in valid_types:
            event_type = "all"
        events = get_latest_events(limit=100, event_type=event_type if event_type != "all" else None)
    
    # For backward compatibility and UI state
    selected_types = event_types if event_types else []
    if not selected_types:
        # Check legacy type parameter
        selected_type = request.args.get("type", "all")
        if selected_type == "all":
            selected_types = ["all"]
        else:
            selected_types = [selected_type]
            event_types = [selected_type]  # Set for filtering logic
    
    # Determine if advanced filter should be shown
    has_active_filters = bool(search_query or (event_types and len(event_types) > 0 and event_types != ["all"]))
    
    # Get event counts for metric cards
    event_counts = get_event_counts()
    
    return render_template(
        "index.html",
        events=events,
        search_query=search_query,
        selected_event_types=selected_types,
        selected_search_columns=search_columns if search_columns else ["all"],
        has_active_filters=has_active_filters,
        event_counts=event_counts
    )


@app.route("/classification/save-all", methods=["POST"])
def classification_save_all():
    """AJAX endpoint to save all classifications at once"""
    import json
    from .models import upsert_file_classification, get_session
    from .orm_models import FileClassification
    
    files_json = request.form.get("files")
    if not files_json:
        return jsonify({"success": False, "message": "Missing files parameter"}), 400
    
    try:
        files = json.loads(files_json)
    except json.JSONDecodeError:
        return jsonify({"success": False, "message": "Invalid JSON format"}), 400
    
    if not isinstance(files, list):
        return jsonify({"success": False, "message": "Files must be a list"}), 400
    
    db = get_session()
    saved_count = 0
    
    try:
        for file_data in files:
            file_path = file_data.get("file_path")
            classification = file_data.get("classification", "").strip()
            endpoint = file_data.get("endpoint")
            hostname = file_data.get("hostname")
            username = file_data.get("username")
            
            if not file_path:
                continue
            
            if not classification:
                # Delete record if classification is empty
                db.query(FileClassification).filter(
                    FileClassification.file_path == file_path
                ).delete()
            else:
                # Update or insert classification using upsert function
                upsert_file_classification(
                    file_path=file_path,
                    classification=classification,
                    endpoint=endpoint,
                    hostname=hostname,
                    username=username
                )
            
            saved_count += 1
        
        db.commit()
    except Exception as e:
        db.rollback()
        return jsonify({"success": False, "message": str(e)}), 500
    finally:
        db.close()
    
    return jsonify({
        "success": True,
        "message": f"Successfully saved {saved_count} classification(s)"
    })


@app.route("/classification/update", methods=["POST"])
def classification_update():
    """AJAX endpoint to update classification without page reload"""
    file_path = request.form.get("file_path")
    classification = request.form.get("classification", "").strip()
    endpoint = request.form.get("endpoint")
    hostname = request.form.get("hostname")
    username = request.form.get("username")
    
    if not file_path:
        return jsonify({"success": False, "message": "Missing file_path parameter"}), 400
    
    # If classification is empty, delete the record to clear it
    if not classification:
        from .models import get_session
        from .orm_models import FileClassification
        db = get_session()
        try:
            db.query(FileClassification).filter(
                FileClassification.file_path == file_path
            ).delete()
            db.commit()
        finally:
            db.close()
        return jsonify({"success": True, "message": "Classification cleared successfully"})
    
    # Update or insert classification
    upsert_file_classification(
        file_path=file_path,
        classification=classification,
        endpoint=endpoint,
        hostname=hostname,
        username=username
    )
    
    return jsonify({"success": True, "message": "Classification updated successfully"})


@app.route("/classification", methods=["GET"])
def classification():
    """Classification page for assigning security levels to files"""
    
    # GET request - display classification page
    # Get endpoint filters
    endpoints_param = request.args.get("endpoints", "")
    if endpoints_param:
        selected_endpoints = [e.strip() for e in endpoints_param.split(",") if e.strip()]
    else:
        selected_endpoints = None
    
    # Get search query for file path
    search_query = request.args.get("search", "").strip()
    
    # Get distinct file paths
    files = get_distinct_file_paths(endpoints=selected_endpoints)
    
    # Filter by search query if provided
    if search_query:
        files = [f for f in files if search_query.lower() in f["file_path"].lower()]
    
    # Get existing classifications
    classifications_dict = {}
    if selected_endpoints:
        classifications = get_all_classifications(endpoints=selected_endpoints)
    else:
        classifications = get_all_classifications()
    
    for cls in classifications:
        classifications_dict[cls["file_path"]] = cls
    
    # Merge file info with classifications
    for file_info in files:
        file_path = file_info["file_path"]
        if file_path in classifications_dict:
            file_info["classification"] = classifications_dict[file_path]["classification"]
            file_info["classification_id"] = classifications_dict[file_path]["id"]
        else:
            file_info["classification"] = None
            file_info["classification_id"] = None
    
    # Get available endpoints for filter
    available_endpoints = get_distinct_endpoints()
    
    return render_template(
        "classification.html",
        files=files,
        available_endpoints=available_endpoints,
        selected_endpoints=selected_endpoints if selected_endpoints else [],
        search_query=search_query
    )


def run_app(host: str = None, port: int = None, debug: bool = False) -> None:
    """Run the Flask application
    
    Args:
        host: Host to bind to (defaults to config value)
        port: Port to bind to (defaults to config value)
        debug: Enable debug mode
    """
    host = host or FLASK_HOST
    port = port or FLASK_PORT
    
    print(f"[FLASK] Starting dashboard on http://{host}:{port}")
    app.run(host=host, port=port, debug=debug, use_reloader=False)

