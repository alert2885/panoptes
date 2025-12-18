import os
import json
from datetime import datetime
from typing import Any, Dict, Optional, List

import asyncpg
from fastapi import FastAPI, HTTPException, Header, Depends, Body
from pydantic import BaseModel, Field, validator
from dotenv import load_dotenv

# ============================
# Load environment variables
# ============================

load_dotenv()  # loads .env into os.environ

DB_HOST = os.getenv("FIM_DB_HOST")
DB_PORT = int(os.getenv("FIM_DB_PORT", "5432"))
DB_NAME = os.getenv("FIM_DB_NAME")
DB_USER = os.getenv("FIM_DB_USER")
DB_PASSWORD = os.getenv("FIM_DB_PASSWORD")

FIM_EVENTS_TABLE = os.getenv("FIM_EVENTS_TABLE", "fim.fim_events")
AGENTS_TABLE = os.getenv("FIM_AGENTS_TABLE", "fim.agents")
AGENT_CONFIGS_TABLE = os.getenv("FIM_AGENT_CONFIGS_TABLE", "fim.agent_configs")

FIM_API_KEY = os.getenv("FIM_API_KEY")

required_vars = [
    "FIM_DB_HOST",
    "FIM_DB_NAME",
    "FIM_DB_USER",
    "FIM_DB_PASSWORD",
    "FIM_API_KEY",
]
missing = [v for v in required_vars if not os.getenv(v)]
if missing:
    raise RuntimeError(f"Missing required environment variables: {', '.join(missing)}")


def verify_api_key(x_api_key: str = Header(...)):
    if x_api_key != FIM_API_KEY:
        # don't leak whether key is wrong vs missing details
        raise HTTPException(status_code=401, detail="Invalid or missing API key")
    return True


# ============================
# Pydantic models (Pydantic v2)
# ============================

class SnapshotModel(BaseModel):
    path: Optional[str] = None
    timestamp: Optional[str] = None
    current_user: Optional[str] = None
    machine: Optional[str] = None

    file_uid: Optional[str] = None

    content_hash: Optional[str] = None
    filesystem_hash: Optional[str] = None
    embedded_metadata_hash: Optional[str] = None
    combined_hash: Optional[str] = None

    filesystem_metadata: Optional[Dict[str, Any]] = None
    embedded_metadata: Optional[Dict[str, Any]] = None

    file_size: Optional[int] = None

    # chunks: { chunk_size, total_chunks, hashes: [] }
    chunks: Optional[Dict[str, Any]] = None


class FIMEventModel(BaseModel):
    agent_id: str
    endpoint: Optional[str] = None
    hostname: Optional[str] = None
    username: Optional[str] = None

    event_type: str = Field(..., pattern="^(CREATED|MODIFIED|DELETED|MOVED)$")
    source: str = Field(..., pattern="^(baseline|realtime)$")

    path: Optional[str] = None
    old_path: Optional[str] = None
    new_path: Optional[str] = None

    timestamp: str  # ISO 8601 string from agent
    snapshot: Optional[SnapshotModel] = None

    # chunk diff summary from agent
    chunk_diff: Optional[Dict[str, Any]] = None

    @validator("timestamp")
    def validate_timestamp(cls, v: str) -> str:
        try:
            if v.endswith("Z"):
                datetime.fromisoformat(v.replace("Z", "+00:00"))
            else:
                datetime.fromisoformat(v)
        except ValueError:
            raise ValueError("timestamp must be ISO-8601 format")
        return v

    @validator("event_type")
    def validate_event_type(cls, v: str) -> str:
        allowed = {"CREATED", "MODIFIED", "DELETED", "MOVED"}
        if v not in allowed:
            raise ValueError(f"event_type must be one of {allowed}")
        return v

    @validator("source")
    def validate_source(cls, v: str) -> str:
        allowed = {"baseline", "realtime"}
        if v not in allowed:
            raise ValueError(f"source must be one of {allowed}")
        return v


# --- Remote management / heartbeat models ---

class AgentHeartbeat(BaseModel):
    agent_id: str
    hostname: Optional[str] = None
    endpoint: Optional[str] = None
    agent_version: Optional[str] = None
    current_config_version: Optional[int] = None  # what the agent currently has


class AgentHeartbeatResponse(BaseModel):
    status: str
    server_time: str
    config_version: Optional[int] = None
    # MUST be a dict, not JSON string
    config: Optional[Dict[str, Any]] = None


class AgentConfigUpsertRequest(BaseModel):
    """
    Used from the central side (e.g. CLI/UI) to push a new config version.
    """
    agent_id: str
    config_json: Dict[str, Any]
    version: Optional[int] = None  # if None, auto-increment


# ============================
# FastAPI app
# ============================

app = FastAPI(title="FIM Agent Handler")


@app.on_event("startup")
async def startup_event():
    app.state.db_pool = await asyncpg.create_pool(
        host=DB_HOST,
        port=DB_PORT,
        user=DB_USER,
        password=DB_PASSWORD,
        database=DB_NAME,
        min_size=1,
        max_size=10,
    )
    print("[*] PostgreSQL connection pool created")


@app.on_event("shutdown")
async def shutdown_event():
    pool = app.state.db_pool
    await pool.close()
    print("[*] PostgreSQL connection pool closed")


# ============================
# Helper: parse ISO time
# ============================

def parse_iso_timestamp(ts: str) -> datetime:
    """
    Convert an ISO-8601 timestamp string to a timezone-aware datetime.
    Supports trailing 'Z' for UTC.
    """
    if ts.endswith("Z"):
        ts = ts.replace("Z", "+00:00")
    return datetime.fromisoformat(ts)


# ============================
# Main FIM event endpoint
# ============================

@app.post("/fim/event")
async def receive_fim_event(
    event: FIMEventModel,
    authorized: bool = Depends(verify_api_key),
):
    """
    Receive a FIM event from an agent and insert into PostgreSQL (fim.fim_events).
    fim.fim_current_state is updated by DB trigger.
    """
    # Parse event timestamp
    try:
        event_time = parse_iso_timestamp(event.timestamp)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid timestamp format")

    # Handle MOVED vs other events
    path: Optional[str] = event.path
    old_path: Optional[str] = event.old_path
    new_path: Optional[str] = event.new_path

    if event.event_type == "MOVED":
        if not old_path or not new_path:
            raise HTTPException(
                status_code=400,
                detail="MOVED event must include old_path and new_path",
            )
        if path is None:
            path = new_path
    else:
        if not path:
            raise HTTPException(
                status_code=400,
                detail=f"{event.event_type} event must include 'path'",
            )

    # Snapshot handling
    snapshot = event.snapshot
    if snapshot is None:
        snapshot_dict: Dict[str, Any] = {}
    else:
        snapshot_dict = snapshot.model_dump()

    # Extract simple fields from snapshot
    file_uid = snapshot_dict.get("file_uid")
    content_hash = snapshot_dict.get("content_hash")
    filesystem_hash = snapshot_dict.get("filesystem_hash")
    embedded_metadata_hash = snapshot_dict.get("embedded_metadata_hash")
    combined_hash = snapshot_dict.get("combined_hash")
    file_size = snapshot_dict.get("file_size")

    # Extract chunk hashes (if present)
    chunks = snapshot_dict.get("chunks")
    if chunks is not None:
        chunk_hashes_json_str = json.dumps(chunks)
    else:
        chunk_hashes_json_str = None

    # Chunk diff (optional)
    chunk_diff = event.chunk_diff
    if chunk_diff is not None:
        chunk_diff_json_str = json.dumps(chunk_diff)
    else:
        chunk_diff_json_str = None

    # snapshot_json must be NOT NULL
    snapshot_json_str = json.dumps(snapshot_dict)

    query = f"""
        INSERT INTO {FIM_EVENTS_TABLE} (
            event_time,
            agent_id,
            endpoint,
            hostname,
            username,
            event_type,
            source,
            path,
            old_path,
            new_path,
            file_uid,
            content_hash,
            filesystem_hash,
            embedded_metadata_hash,
            combined_hash,
            file_size,
            snapshot_json,
            chunk_hashes_json,
            chunk_diff_json
        ) VALUES (
            $1,  $2,  $3,  $4,  $5,
            $6,  $7,
            $8,  $9,  $10,
            $11,
            $12, $13, $14, $15,
            $16,
            $17::jsonb,
            $18::jsonb,
            $19::jsonb
        )
        RETURNING id, received_at;
    """

    pool: asyncpg.pool.Pool = app.state.db_pool

    try:
        async with pool.acquire() as conn:
            row = await conn.fetchrow(
                query,
                event_time,
                event.agent_id,
                event.endpoint,
                event.hostname,
                event.username,
                event.event_type,
                event.source,
                path,
                old_path,
                new_path,
                file_uid,
                content_hash,
                filesystem_hash,
                embedded_metadata_hash,
                combined_hash,
                file_size,
                snapshot_json_str,
                chunk_hashes_json_str,
                chunk_diff_json_str,
            )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"DB insert failed: {e}")

    return {
        "status": "ok",
        "id": row["id"],
        "received_at": row["received_at"].isoformat(),
    }


# ============================
# Agent heartbeat & config pull
# ============================

@app.post("/fim/agent/heartbeat", response_model=AgentHeartbeatResponse)
async def agent_heartbeat(
    hb: AgentHeartbeat,
    authorized: bool = Depends(verify_api_key),
):
    """
    - Upsert agent row in fim.agents
    - Optionally return a newer config if available
    """
    now = datetime.utcnow().isoformat() + "Z"
    pool: asyncpg.pool.Pool = app.state.db_pool

    async with pool.acquire() as conn:
        # 1) upsert agent
        await conn.execute(
            f"""
            INSERT INTO {AGENTS_TABLE} (
                agent_id,
                hostname,
                endpoint,
                last_seen,
                agent_version,
                current_config_version
            )
            VALUES ($1, $2, $3, now(), $4, $5)
            ON CONFLICT (agent_id) DO UPDATE SET
                hostname = EXCLUDED.hostname,
                endpoint = EXCLUDED.endpoint,
                last_seen = now(),
                agent_version = EXCLUDED.agent_version,
                current_config_version = EXCLUDED.current_config_version;
            """,
            hb.agent_id,
            hb.hostname,
            hb.endpoint,
            hb.agent_version,
            hb.current_config_version,
        )

        # 2) get latest config (if any) for this agent
        cfg_row = await conn.fetchrow(
            f"""
            SELECT version, config_json
            FROM {AGENT_CONFIGS_TABLE}
            WHERE agent_id = $1
            ORDER BY version DESC
            LIMIT 1;
            """,
            hb.agent_id,
        )

    # no config exists in DB for this agent yet
    if not cfg_row:
        return AgentHeartbeatResponse(
            status="ok",
            server_time=now,
            config_version=None,
            config=None,
        )

    latest_version: int = cfg_row["version"]
    raw_cfg = cfg_row["config_json"]

    # 🔧 Normalize to dict (handle jsonb containing either object or scalar string)
    if isinstance(raw_cfg, dict):
        config_json: Dict[str, Any] = raw_cfg
    elif isinstance(raw_cfg, str):
        try:
            config_json = json.loads(raw_cfg)
        except Exception as e:
            raise HTTPException(
                status_code=500,
                detail=f"Invalid config_json format in DB for agent {hb.agent_id}: {e}",
            )
    else:
        # last-resort fallback
        config_json = json.loads(json.dumps(raw_cfg, default=str))

    # Decide whether to send config
    send_config = False
    if hb.current_config_version is None:
        send_config = True
    elif hb.current_config_version < latest_version:
        send_config = True

    if not send_config:
        # agent is already up-to-date (or ahead)
        return AgentHeartbeatResponse(
            status="ok",
            server_time=now,
            config_version=hb.current_config_version,
            config=None,
        )

    # ✅ Return a proper dict to Pydantic
    return AgentHeartbeatResponse(
        status="ok",
        server_time=now,
        config_version=latest_version,
        config=config_json,
    )


# ============================
# Remote config management
# ============================

@app.post("/fim/agent/config", dependencies=[Depends(verify_api_key)])
async def upsert_agent_config(
    req: AgentConfigUpsertRequest = Body(...),
):
    """
    Create a new config version for an agent.

    - If req.version is provided -> use it (error if already exists).
    - If req.version is None -> auto-increment from max(version)+1.
    """
    pool: asyncpg.pool.Pool = app.state.db_pool

    async with pool.acquire() as conn:
        if req.version is None:
            # get next version
            row = await conn.fetchrow(
                f"""
                SELECT COALESCE(MAX(version), 0) + 1 AS next_version
                FROM {AGENT_CONFIGS_TABLE}
                WHERE agent_id = $1;
                """,
                req.agent_id,
            )
            next_version = row["next_version"]
        else:
            next_version = req.version

        try:
            await conn.execute(
                f"""
                INSERT INTO {AGENT_CONFIGS_TABLE} (agent_id, version, config_json)
                VALUES ($1, $2, $3::jsonb);
                """,
                req.agent_id,
                next_version,
                req.config_json,  # pass dict, let asyncpg handle -> jsonb
            )
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Failed to insert agent config: {e}")

    return {
        "status": "ok",
        "agent_id": req.agent_id,
        "version": next_version,
    }


@app.get("/fim/agent/{agent_id}/config", dependencies=[Depends(verify_api_key)])
async def get_latest_config(agent_id: str):
    """
    Fetch the latest config for a given agent_id.
    """
    pool: asyncpg.pool.Pool = app.state.db_pool
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            f"""
            SELECT version, config_json, created_at
            FROM {AGENT_CONFIGS_TABLE}
            WHERE agent_id = $1
            ORDER BY version DESC
            LIMIT 1;
            """,
            agent_id,
        )

    if not row:
        raise HTTPException(status_code=404, detail="No config found for this agent")

    raw_cfg = row["config_json"]
    if isinstance(raw_cfg, dict):
        cfg = raw_cfg
    elif isinstance(raw_cfg, str):
        cfg = json.loads(raw_cfg)
    else:
        cfg = json.loads(json.dumps(raw_cfg, default=str))

    return {
        "agent_id": agent_id,
        "version": row["version"],
        "config": cfg,
        "created_at": row["created_at"].isoformat(),
    }


@app.get("/fim/agents", dependencies=[Depends(verify_api_key)])
async def list_agents():
    """
    List all known agents with basic info.
    """
    pool: asyncpg.pool.Pool = app.state.db_pool
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            f"""
            SELECT
                agent_id,
                hostname,
                endpoint,
                last_seen,
                agent_version,
                current_config_version
            FROM {AGENTS_TABLE}
            ORDER BY agent_id;
            """
        )

    agents: List[Dict[str, Any]] = []
    for r in rows:
        agents.append(
            {
                "agent_id": r["agent_id"],
                "hostname": r["hostname"],
                "endpoint": r["endpoint"],
                "last_seen": r["last_seen"].isoformat() if r["last_seen"] else None,
                "agent_version": r["agent_version"],
                "current_config_version": r["current_config_version"],
            }
        )

    return {"agents": agents}


# ============================
# Health check
# ============================

@app.get("/health")
async def health():
    return {"status": "up"}
