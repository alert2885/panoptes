--
-- PostgreSQL database dump
--

\restrict ebWSAHo30PIndxWbglip5tfMoocehqKL1z7OGNG02uVCbbdHpn0EbQBxbEBVbZS

-- Dumped from database version 14.20 (Ubuntu 14.20-0ubuntu0.22.04.1)
-- Dumped by pg_dump version 14.20 (Ubuntu 14.20-0ubuntu0.22.04.1)

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: fim_db; Type: DATABASE; Schema: -; Owner: -
--

CREATE DATABASE fim_db WITH TEMPLATE = template0 ENCODING = 'UTF8' LOCALE = 'en_US.UTF-8';


\unrestrict ebWSAHo30PIndxWbglip5tfMoocehqKL1z7OGNG02uVCbbdHpn0EbQBxbEBVbZS
\connect fim_db
\restrict ebWSAHo30PIndxWbglip5tfMoocehqKL1z7OGNG02uVCbbdHpn0EbQBxbEBVbZS

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: fim; Type: SCHEMA; Schema: -; Owner: -
--

CREATE SCHEMA fim;


--
-- Name: integrity_level; Type: TYPE; Schema: fim; Owner: -
--

CREATE TYPE fim.integrity_level AS ENUM (
    'Standard',
    'Critical',
    'Write-Protected',
    'Immutable',
    'Unclassified'
);


--
-- Name: apply_integrity_policy(); Type: FUNCTION; Schema: fim; Owner: -
--

CREATE FUNCTION fim.apply_integrity_policy() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    v_integrity fim.integrity_level;
BEGIN
    -- Default: Unclassified (no decision yet)
    v_integrity := 'Unclassified';

    -- If we have a file_uid, try to load policy
    IF NEW.file_uid IS NOT NULL THEN
        SELECT p.integrity
          INTO v_integrity
          FROM fim.file_integrity_policy p
         WHERE p.file_uid = NEW.file_uid;
    END IF;

    -- If policy lookup produced NULL, keep Unclassified
    IF v_integrity IS NULL THEN
        v_integrity := 'Unclassified';
    END IF;

    NEW.integrity := v_integrity;

    CASE v_integrity
        WHEN 'Immutable' THEN
            NEW.severity := 10;
            NEW.policy_violation := (NEW.event_type IN ('MODIFIED','DELETED','MOVED'));

        WHEN 'Write-Protected' THEN
            NEW.severity := 8;
            NEW.policy_violation := (NEW.event_type IN ('MODIFIED','DELETED','MOVED'));

        WHEN 'Critical' THEN
            NEW.severity := 6;
            NEW.policy_violation := FALSE;

        ELSE
            -- Standard + Unclassified land here
            NEW.severity := 1;
            NEW.policy_violation := FALSE;
    END CASE;

    RETURN NEW;
END;
$$;


--
-- Name: sync_current_state(); Type: FUNCTION; Schema: fim; Owner: -
--

CREATE FUNCTION fim.sync_current_state() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    v_source text;
    v_reason text;
BEGIN
    -- Pull policy metadata (if any)
    v_source := 'default';
    v_reason := NULL;

    IF NEW.file_uid IS NOT NULL THEN
        SELECT p.source, p.reason
          INTO v_source, v_reason
          FROM fim.file_integrity_policy p
         WHERE p.file_uid = NEW.file_uid;
    END IF;

    IF v_source IS NULL THEN
        v_source := 'default';
    END IF;

    INSERT INTO fim.fim_current_state (
        agent_id,
        endpoint,
        hostname,
        file_uid,
        path,
        last_event_id,
        last_event_time,
        last_event_type,
        is_deleted,
        content_hash,
        filesystem_hash,
        embedded_metadata_hash,
        combined_hash,
        file_size,
        snapshot_json,
        chunk_hashes_json,
        integrity,
        integrity_source,
        integrity_reason
    )
    VALUES (
        NEW.agent_id,
        NEW.endpoint,
        NEW.hostname,
        NEW.file_uid,
        COALESCE(NEW.new_path, NEW.path),
        NEW.id,
        NEW.event_time,
        NEW.event_type,
        (NEW.event_type = 'DELETED'),
        NEW.content_hash,
        NEW.filesystem_hash,
        NEW.embedded_metadata_hash,
        NEW.combined_hash,
        NEW.file_size,
        NEW.snapshot_json,
        NEW.chunk_hashes_json,
        COALESCE(NEW.integrity, 'Standard'),
        v_source,
        v_reason
    )
    ON CONFLICT (agent_id, file_uid)
    DO UPDATE SET
        path = EXCLUDED.path,
        last_event_id = EXCLUDED.last_event_id,
        last_event_time = EXCLUDED.last_event_time,
        last_event_type = EXCLUDED.last_event_type,
        is_deleted = EXCLUDED.is_deleted,
        content_hash = EXCLUDED.content_hash,
        filesystem_hash = EXCLUDED.filesystem_hash,
        embedded_metadata_hash = EXCLUDED.embedded_metadata_hash,
        combined_hash = EXCLUDED.combined_hash,
        file_size = EXCLUDED.file_size,
        snapshot_json = EXCLUDED.snapshot_json,
        chunk_hashes_json = EXCLUDED.chunk_hashes_json,
        integrity = EXCLUDED.integrity,
        integrity_source = EXCLUDED.integrity_source,
        integrity_reason = EXCLUDED.integrity_reason;

    RETURN NEW;
END;
$$;


SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: admin_users; Type: TABLE; Schema: fim; Owner: -
--

CREATE TABLE fim.admin_users (
    id bigint NOT NULL,
    username text NOT NULL,
    password_hash text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: admin_users_id_seq; Type: SEQUENCE; Schema: fim; Owner: -
--

CREATE SEQUENCE fim.admin_users_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: admin_users_id_seq; Type: SEQUENCE OWNED BY; Schema: fim; Owner: -
--

ALTER SEQUENCE fim.admin_users_id_seq OWNED BY fim.admin_users.id;


--
-- Name: agent_commands; Type: TABLE; Schema: fim; Owner: -
--

CREATE TABLE fim.agent_commands (
    id bigint NOT NULL,
    agent_id text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    command_type text NOT NULL,
    payload jsonb,
    status text DEFAULT 'pending'::text NOT NULL,
    last_updated timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: agent_commands_id_seq; Type: SEQUENCE; Schema: fim; Owner: -
--

CREATE SEQUENCE fim.agent_commands_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: agent_commands_id_seq; Type: SEQUENCE OWNED BY; Schema: fim; Owner: -
--

ALTER SEQUENCE fim.agent_commands_id_seq OWNED BY fim.agent_commands.id;


--
-- Name: agent_configs; Type: TABLE; Schema: fim; Owner: -
--

CREATE TABLE fim.agent_configs (
    id bigint NOT NULL,
    agent_id text NOT NULL,
    version integer NOT NULL,
    config_json jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: agent_configs_id_seq; Type: SEQUENCE; Schema: fim; Owner: -
--

CREATE SEQUENCE fim.agent_configs_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: agent_configs_id_seq; Type: SEQUENCE OWNED BY; Schema: fim; Owner: -
--

ALTER SEQUENCE fim.agent_configs_id_seq OWNED BY fim.agent_configs.id;


--
-- Name: agents; Type: TABLE; Schema: fim; Owner: -
--

CREATE TABLE fim.agents (
    id bigint NOT NULL,
    agent_id text NOT NULL,
    hostname text,
    endpoint text,
    last_seen timestamp with time zone,
    agent_version text,
    current_config_version integer,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: agents_id_seq; Type: SEQUENCE; Schema: fim; Owner: -
--

CREATE SEQUENCE fim.agents_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: agents_id_seq; Type: SEQUENCE OWNED BY; Schema: fim; Owner: -
--

ALTER SEQUENCE fim.agents_id_seq OWNED BY fim.agents.id;


--
-- Name: alert_config; Type: TABLE; Schema: fim; Owner: -
--

CREATE TABLE fim.alert_config (
    id bigint NOT NULL,
    alert_name text NOT NULL,
    alert_type text NOT NULL,
    min_severity smallint,
    event_types jsonb,
    integrity_levels jsonb,
    endpoints jsonb,
    enabled boolean NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: alert_config_id_seq; Type: SEQUENCE; Schema: fim; Owner: -
--

CREATE SEQUENCE fim.alert_config_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: alert_config_id_seq; Type: SEQUENCE OWNED BY; Schema: fim; Owner: -
--

ALTER SEQUENCE fim.alert_config_id_seq OWNED BY fim.alert_config.id;


--
-- Name: alert_history; Type: TABLE; Schema: fim; Owner: -
--

CREATE TABLE fim.alert_history (
    id bigint NOT NULL,
    event_id bigint NOT NULL,
    alert_type text NOT NULL,
    alert_message text,
    sent_timestamp timestamp with time zone DEFAULT now() NOT NULL,
    endpoint text,
    status text
);


--
-- Name: alert_history_id_seq; Type: SEQUENCE; Schema: fim; Owner: -
--

CREATE SEQUENCE fim.alert_history_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: alert_history_id_seq; Type: SEQUENCE OWNED BY; Schema: fim; Owner: -
--

ALTER SEQUENCE fim.alert_history_id_seq OWNED BY fim.alert_history.id;


--
-- Name: alert_notifications; Type: TABLE; Schema: fim; Owner: -
--

CREATE TABLE fim.alert_notifications (
    event_id bigint NOT NULL,
    channel text NOT NULL,
    sent_at timestamp with time zone DEFAULT now() NOT NULL,
    status text DEFAULT 'sent'::text NOT NULL,
    error text
);


--
-- Name: app_settings; Type: TABLE; Schema: fim; Owner: -
--

CREATE TABLE fim.app_settings (
    id integer NOT NULL,
    settings_json jsonb NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: baseline_items; Type: TABLE; Schema: fim; Owner: -
--

CREATE TABLE fim.baseline_items (
    id bigint NOT NULL,
    baseline_id bigint NOT NULL,
    file_uid text NOT NULL,
    file_path text NOT NULL,
    hash text,
    size_bytes bigint,
    mtime timestamp with time zone,
    integrity character varying(32) DEFAULT 'Standard'::character varying NOT NULL,
    captured_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: baseline_items_id_seq; Type: SEQUENCE; Schema: fim; Owner: -
--

CREATE SEQUENCE fim.baseline_items_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: baseline_items_id_seq; Type: SEQUENCE OWNED BY; Schema: fim; Owner: -
--

ALTER SEQUENCE fim.baseline_items_id_seq OWNED BY fim.baseline_items.id;


--
-- Name: baselines; Type: TABLE; Schema: fim; Owner: -
--

CREATE TABLE fim.baselines (
    id bigint NOT NULL,
    agent_id text NOT NULL,
    endpoint text NOT NULL,
    scope_path text,
    include_patterns jsonb,
    exclude_patterns jsonb,
    status character varying(16) DEFAULT 'ACTIVE'::character varying NOT NULL,
    version integer NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    created_by text,
    notes text
);


--
-- Name: baselines_id_seq; Type: SEQUENCE; Schema: fim; Owner: -
--

CREATE SEQUENCE fim.baselines_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: baselines_id_seq; Type: SEQUENCE OWNED BY; Schema: fim; Owner: -
--

ALTER SEQUENCE fim.baselines_id_seq OWNED BY fim.baselines.id;


--
-- Name: file_classifications; Type: TABLE; Schema: fim; Owner: -
--

CREATE TABLE fim.file_classifications (
    id bigint NOT NULL,
    file_path text NOT NULL,
    classification text NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: file_classifications_id_seq; Type: SEQUENCE; Schema: fim; Owner: -
--

CREATE SEQUENCE fim.file_classifications_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: file_classifications_id_seq; Type: SEQUENCE OWNED BY; Schema: fim; Owner: -
--

ALTER SEQUENCE fim.file_classifications_id_seq OWNED BY fim.file_classifications.id;


--
-- Name: file_integrity_policy; Type: TABLE; Schema: fim; Owner: -
--

CREATE TABLE fim.file_integrity_policy (
    file_uid text NOT NULL,
    integrity fim.integrity_level DEFAULT 'Unclassified'::fim.integrity_level NOT NULL,
    source text DEFAULT 'manual'::text NOT NULL,
    reason text,
    set_by text,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT file_integrity_policy_source_check CHECK ((source = ANY (ARRAY['manual'::text, 'rule'::text])))
);


--
-- Name: fim_current_state; Type: TABLE; Schema: fim; Owner: -
--

CREATE TABLE fim.fim_current_state (
    id bigint NOT NULL,
    agent_id text NOT NULL,
    endpoint text,
    hostname text,
    file_uid text NOT NULL,
    path text NOT NULL,
    last_event_id bigint NOT NULL,
    last_event_time timestamp with time zone NOT NULL,
    last_event_type character varying(16) NOT NULL,
    is_deleted boolean DEFAULT false NOT NULL,
    content_hash character(64),
    filesystem_hash character(64),
    embedded_metadata_hash character(64),
    combined_hash character(64),
    file_size bigint,
    snapshot_json jsonb NOT NULL,
    chunk_hashes_json jsonb,
    integrity fim.integrity_level DEFAULT 'Unclassified'::fim.integrity_level NOT NULL,
    integrity_source text DEFAULT 'manual'::text NOT NULL,
    integrity_reason text,
    CONSTRAINT fim_current_state_integrity_source_check CHECK ((integrity_source = ANY (ARRAY['manual'::text, 'rule'::text, 'default'::text]))),
    CONSTRAINT fim_current_state_last_event_type_check CHECK (((last_event_type)::text = ANY ((ARRAY['CREATED'::character varying, 'MODIFIED'::character varying, 'MOVED'::character varying, 'DELETED'::character varying])::text[])))
);


--
-- Name: fim_current_state_id_seq; Type: SEQUENCE; Schema: fim; Owner: -
--

CREATE SEQUENCE fim.fim_current_state_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: fim_current_state_id_seq; Type: SEQUENCE OWNED BY; Schema: fim; Owner: -
--

ALTER SEQUENCE fim.fim_current_state_id_seq OWNED BY fim.fim_current_state.id;


--
-- Name: fim_events; Type: TABLE; Schema: fim; Owner: -
--

CREATE TABLE fim.fim_events (
    id bigint NOT NULL,
    received_at timestamp with time zone DEFAULT now() NOT NULL,
    event_time timestamp with time zone NOT NULL,
    agent_id text NOT NULL,
    endpoint text,
    hostname text,
    username text,
    event_type character varying(16) NOT NULL,
    source character varying(16) NOT NULL,
    path text,
    old_path text,
    new_path text,
    file_uid text,
    content_hash character(64),
    filesystem_hash character(64),
    embedded_metadata_hash character(64),
    combined_hash character(64),
    file_size bigint,
    snapshot_json jsonb NOT NULL,
    chunk_hashes_json jsonb,
    chunk_diff_json jsonb,
    integrity fim.integrity_level,
    severity smallint DEFAULT 1 NOT NULL,
    policy_violation boolean DEFAULT false NOT NULL,
    CONSTRAINT fim_events_event_type_check CHECK (((event_type)::text = ANY ((ARRAY['CREATED'::character varying, 'MODIFIED'::character varying, 'DELETED'::character varying, 'MOVED'::character varying])::text[]))),
    CONSTRAINT fim_events_source_check CHECK (((source)::text = ANY ((ARRAY['baseline'::character varying, 'realtime'::character varying])::text[])))
);


--
-- Name: fim_events_id_seq; Type: SEQUENCE; Schema: fim; Owner: -
--

CREATE SEQUENCE fim.fim_events_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: fim_events_id_seq; Type: SEQUENCE OWNED BY; Schema: fim; Owner: -
--

ALTER SEQUENCE fim.fim_events_id_seq OWNED BY fim.fim_events.id;


--
-- Name: hash_baselines; Type: TABLE; Schema: fim; Owner: -
--

CREATE TABLE fim.hash_baselines (
    id bigint NOT NULL,
    file_path text NOT NULL,
    hash_value text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: hash_baselines_id_seq; Type: SEQUENCE; Schema: fim; Owner: -
--

CREATE SEQUENCE fim.hash_baselines_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: hash_baselines_id_seq; Type: SEQUENCE OWNED BY; Schema: fim; Owner: -
--

ALTER SEQUENCE fim.hash_baselines_id_seq OWNED BY fim.hash_baselines.id;


--
-- Name: alert_config; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.alert_config (
    id integer NOT NULL,
    config_name character varying(255) NOT NULL,
    config_value text,
    enabled boolean,
    updated_timestamp character varying(50) NOT NULL
);


--
-- Name: alert_config_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.alert_config_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: alert_config_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.alert_config_id_seq OWNED BY public.alert_config.id;


--
-- Name: alert_history; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.alert_history (
    id integer NOT NULL,
    event_id integer,
    alert_type character varying(50) NOT NULL,
    alert_message text NOT NULL,
    sent_timestamp character varying(50) NOT NULL,
    endpoint character varying(255),
    status character varying(50)
);


--
-- Name: alert_history_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.alert_history_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: alert_history_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.alert_history_id_seq OWNED BY public.alert_history.id;


--
-- Name: events; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.events (
    id integer NOT NULL,
    event_type character varying(50) NOT NULL,
    file_path text NOT NULL,
    "timestamp" character varying(50) NOT NULL,
    endpoint character varying(255) NOT NULL,
    hostname character varying(255) NOT NULL,
    username character varying(255) NOT NULL,
    hash_before text,
    hash_after text,
    state_hash text,
    content_hash text,
    file_size integer,
    metadata_json json,
    alert_sent boolean
);


--
-- Name: events_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.events_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: events_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.events_id_seq OWNED BY public.events.id;


--
-- Name: file_classification; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.file_classification (
    id integer NOT NULL,
    file_path text NOT NULL,
    classification character varying(50) NOT NULL,
    last_updated_timestamp character varying(50) NOT NULL,
    endpoint character varying(255),
    hostname character varying(255),
    username character varying(255)
);


--
-- Name: file_classification_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.file_classification_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: file_classification_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.file_classification_id_seq OWNED BY public.file_classification.id;


--
-- Name: hash_baseline; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.hash_baseline (
    id integer NOT NULL,
    file_path text NOT NULL,
    hash_value text NOT NULL,
    created_timestamp character varying(50) NOT NULL,
    endpoint character varying(255)
);


--
-- Name: hash_baseline_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.hash_baseline_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: hash_baseline_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.hash_baseline_id_seq OWNED BY public.hash_baseline.id;


--
-- Name: sysmon_events; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.sysmon_events (
    id bigint NOT NULL,
    es_index text NOT NULL,
    es_id text NOT NULL,
    event_timestamp timestamp with time zone NOT NULL,
    host text,
    event_code integer,
    channel text,
    record_id bigint,
    event jsonb NOT NULL,
    ingest_ts timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: sysmon_events_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.sysmon_events_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: sysmon_events_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.sysmon_events_id_seq OWNED BY public.sysmon_events.id;


--
-- Name: admin_users id; Type: DEFAULT; Schema: fim; Owner: -
--

ALTER TABLE ONLY fim.admin_users ALTER COLUMN id SET DEFAULT nextval('fim.admin_users_id_seq'::regclass);


--
-- Name: agent_commands id; Type: DEFAULT; Schema: fim; Owner: -
--

ALTER TABLE ONLY fim.agent_commands ALTER COLUMN id SET DEFAULT nextval('fim.agent_commands_id_seq'::regclass);


--
-- Name: agent_configs id; Type: DEFAULT; Schema: fim; Owner: -
--

ALTER TABLE ONLY fim.agent_configs ALTER COLUMN id SET DEFAULT nextval('fim.agent_configs_id_seq'::regclass);


--
-- Name: agents id; Type: DEFAULT; Schema: fim; Owner: -
--

ALTER TABLE ONLY fim.agents ALTER COLUMN id SET DEFAULT nextval('fim.agents_id_seq'::regclass);


--
-- Name: alert_config id; Type: DEFAULT; Schema: fim; Owner: -
--

ALTER TABLE ONLY fim.alert_config ALTER COLUMN id SET DEFAULT nextval('fim.alert_config_id_seq'::regclass);


--
-- Name: alert_history id; Type: DEFAULT; Schema: fim; Owner: -
--

ALTER TABLE ONLY fim.alert_history ALTER COLUMN id SET DEFAULT nextval('fim.alert_history_id_seq'::regclass);


--
-- Name: baseline_items id; Type: DEFAULT; Schema: fim; Owner: -
--

ALTER TABLE ONLY fim.baseline_items ALTER COLUMN id SET DEFAULT nextval('fim.baseline_items_id_seq'::regclass);


--
-- Name: baselines id; Type: DEFAULT; Schema: fim; Owner: -
--

ALTER TABLE ONLY fim.baselines ALTER COLUMN id SET DEFAULT nextval('fim.baselines_id_seq'::regclass);


--
-- Name: file_classifications id; Type: DEFAULT; Schema: fim; Owner: -
--

ALTER TABLE ONLY fim.file_classifications ALTER COLUMN id SET DEFAULT nextval('fim.file_classifications_id_seq'::regclass);


--
-- Name: fim_current_state id; Type: DEFAULT; Schema: fim; Owner: -
--

ALTER TABLE ONLY fim.fim_current_state ALTER COLUMN id SET DEFAULT nextval('fim.fim_current_state_id_seq'::regclass);


--
-- Name: fim_events id; Type: DEFAULT; Schema: fim; Owner: -
--

ALTER TABLE ONLY fim.fim_events ALTER COLUMN id SET DEFAULT nextval('fim.fim_events_id_seq'::regclass);


--
-- Name: hash_baselines id; Type: DEFAULT; Schema: fim; Owner: -
--

ALTER TABLE ONLY fim.hash_baselines ALTER COLUMN id SET DEFAULT nextval('fim.hash_baselines_id_seq'::regclass);


--
-- Name: alert_config id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.alert_config ALTER COLUMN id SET DEFAULT nextval('public.alert_config_id_seq'::regclass);


--
-- Name: alert_history id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.alert_history ALTER COLUMN id SET DEFAULT nextval('public.alert_history_id_seq'::regclass);


--
-- Name: events id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.events ALTER COLUMN id SET DEFAULT nextval('public.events_id_seq'::regclass);


--
-- Name: file_classification id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.file_classification ALTER COLUMN id SET DEFAULT nextval('public.file_classification_id_seq'::regclass);


--
-- Name: hash_baseline id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.hash_baseline ALTER COLUMN id SET DEFAULT nextval('public.hash_baseline_id_seq'::regclass);


--
-- Name: sysmon_events id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sysmon_events ALTER COLUMN id SET DEFAULT nextval('public.sysmon_events_id_seq'::regclass);


--
-- Name: admin_users admin_users_pkey; Type: CONSTRAINT; Schema: fim; Owner: -
--

ALTER TABLE ONLY fim.admin_users
    ADD CONSTRAINT admin_users_pkey PRIMARY KEY (id);


--
-- Name: admin_users admin_users_username_key; Type: CONSTRAINT; Schema: fim; Owner: -
--

ALTER TABLE ONLY fim.admin_users
    ADD CONSTRAINT admin_users_username_key UNIQUE (username);


--
-- Name: agent_commands agent_commands_pkey; Type: CONSTRAINT; Schema: fim; Owner: -
--

ALTER TABLE ONLY fim.agent_commands
    ADD CONSTRAINT agent_commands_pkey PRIMARY KEY (id);


--
-- Name: agent_configs agent_configs_agent_id_version_key; Type: CONSTRAINT; Schema: fim; Owner: -
--

ALTER TABLE ONLY fim.agent_configs
    ADD CONSTRAINT agent_configs_agent_id_version_key UNIQUE (agent_id, version);


--
-- Name: agent_configs agent_configs_pkey; Type: CONSTRAINT; Schema: fim; Owner: -
--

ALTER TABLE ONLY fim.agent_configs
    ADD CONSTRAINT agent_configs_pkey PRIMARY KEY (id);


--
-- Name: agents agents_agent_id_key; Type: CONSTRAINT; Schema: fim; Owner: -
--

ALTER TABLE ONLY fim.agents
    ADD CONSTRAINT agents_agent_id_key UNIQUE (agent_id);


--
-- Name: agents agents_pkey; Type: CONSTRAINT; Schema: fim; Owner: -
--

ALTER TABLE ONLY fim.agents
    ADD CONSTRAINT agents_pkey PRIMARY KEY (id);


--
-- Name: alert_config alert_config_pkey; Type: CONSTRAINT; Schema: fim; Owner: -
--

ALTER TABLE ONLY fim.alert_config
    ADD CONSTRAINT alert_config_pkey PRIMARY KEY (id);


--
-- Name: alert_history alert_history_pkey; Type: CONSTRAINT; Schema: fim; Owner: -
--

ALTER TABLE ONLY fim.alert_history
    ADD CONSTRAINT alert_history_pkey PRIMARY KEY (id);


--
-- Name: alert_notifications alert_notifications_pkey; Type: CONSTRAINT; Schema: fim; Owner: -
--

ALTER TABLE ONLY fim.alert_notifications
    ADD CONSTRAINT alert_notifications_pkey PRIMARY KEY (event_id);


--
-- Name: app_settings app_settings_pkey; Type: CONSTRAINT; Schema: fim; Owner: -
--

ALTER TABLE ONLY fim.app_settings
    ADD CONSTRAINT app_settings_pkey PRIMARY KEY (id);


--
-- Name: baseline_items baseline_items_pkey; Type: CONSTRAINT; Schema: fim; Owner: -
--

ALTER TABLE ONLY fim.baseline_items
    ADD CONSTRAINT baseline_items_pkey PRIMARY KEY (id);


--
-- Name: baselines baselines_pkey; Type: CONSTRAINT; Schema: fim; Owner: -
--

ALTER TABLE ONLY fim.baselines
    ADD CONSTRAINT baselines_pkey PRIMARY KEY (id);


--
-- Name: file_classifications file_classifications_pkey; Type: CONSTRAINT; Schema: fim; Owner: -
--

ALTER TABLE ONLY fim.file_classifications
    ADD CONSTRAINT file_classifications_pkey PRIMARY KEY (id);


--
-- Name: file_integrity_policy file_integrity_policy_pkey; Type: CONSTRAINT; Schema: fim; Owner: -
--

ALTER TABLE ONLY fim.file_integrity_policy
    ADD CONSTRAINT file_integrity_policy_pkey PRIMARY KEY (file_uid);


--
-- Name: fim_current_state fim_current_state_pkey; Type: CONSTRAINT; Schema: fim; Owner: -
--

ALTER TABLE ONLY fim.fim_current_state
    ADD CONSTRAINT fim_current_state_pkey PRIMARY KEY (id);


--
-- Name: fim_events fim_events_pkey; Type: CONSTRAINT; Schema: fim; Owner: -
--

ALTER TABLE ONLY fim.fim_events
    ADD CONSTRAINT fim_events_pkey PRIMARY KEY (id);


--
-- Name: hash_baselines hash_baselines_pkey; Type: CONSTRAINT; Schema: fim; Owner: -
--

ALTER TABLE ONLY fim.hash_baselines
    ADD CONSTRAINT hash_baselines_pkey PRIMARY KEY (id);


--
-- Name: alert_config alert_config_config_name_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.alert_config
    ADD CONSTRAINT alert_config_config_name_key UNIQUE (config_name);


--
-- Name: alert_config alert_config_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.alert_config
    ADD CONSTRAINT alert_config_pkey PRIMARY KEY (id);


--
-- Name: alert_history alert_history_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.alert_history
    ADD CONSTRAINT alert_history_pkey PRIMARY KEY (id);


--
-- Name: events events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.events
    ADD CONSTRAINT events_pkey PRIMARY KEY (id);


--
-- Name: file_classification file_classification_file_path_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.file_classification
    ADD CONSTRAINT file_classification_file_path_key UNIQUE (file_path);


--
-- Name: file_classification file_classification_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.file_classification
    ADD CONSTRAINT file_classification_pkey PRIMARY KEY (id);


--
-- Name: hash_baseline hash_baseline_file_path_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.hash_baseline
    ADD CONSTRAINT hash_baseline_file_path_key UNIQUE (file_path);


--
-- Name: hash_baseline hash_baseline_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.hash_baseline
    ADD CONSTRAINT hash_baseline_pkey PRIMARY KEY (id);


--
-- Name: sysmon_events sysmon_events_es_index_es_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sysmon_events
    ADD CONSTRAINT sysmon_events_es_index_es_id_key UNIQUE (es_index, es_id);


--
-- Name: sysmon_events sysmon_events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sysmon_events
    ADD CONSTRAINT sysmon_events_pkey PRIMARY KEY (id);


--
-- Name: idx_agent_commands_pending; Type: INDEX; Schema: fim; Owner: -
--

CREATE INDEX idx_agent_commands_pending ON fim.agent_commands USING btree (agent_id, status, created_at);


--
-- Name: idx_app_settings_id; Type: INDEX; Schema: fim; Owner: -
--

CREATE INDEX idx_app_settings_id ON fim.app_settings USING btree (id);


--
-- Name: idx_baseline_items_baseline_file_uid; Type: INDEX; Schema: fim; Owner: -
--

CREATE INDEX idx_baseline_items_baseline_file_uid ON fim.baseline_items USING btree (baseline_id, file_uid);


--
-- Name: idx_baseline_items_baseline_id; Type: INDEX; Schema: fim; Owner: -
--

CREATE INDEX idx_baseline_items_baseline_id ON fim.baseline_items USING btree (baseline_id);


--
-- Name: idx_baseline_items_baseline_path; Type: INDEX; Schema: fim; Owner: -
--

CREATE INDEX idx_baseline_items_baseline_path ON fim.baseline_items USING btree (baseline_id, file_path);


--
-- Name: idx_baselines_agent_scope_version; Type: INDEX; Schema: fim; Owner: -
--

CREATE INDEX idx_baselines_agent_scope_version ON fim.baselines USING btree (agent_id, scope_path, version);


--
-- Name: idx_baselines_agent_status; Type: INDEX; Schema: fim; Owner: -
--

CREATE INDEX idx_baselines_agent_status ON fim.baselines USING btree (agent_id, status);


--
-- Name: idx_baselines_endpoint; Type: INDEX; Schema: fim; Owner: -
--

CREATE INDEX idx_baselines_endpoint ON fim.baselines USING btree (endpoint);


--
-- Name: idx_fim_current_state_agent_file_uid; Type: INDEX; Schema: fim; Owner: -
--

CREATE UNIQUE INDEX idx_fim_current_state_agent_file_uid ON fim.fim_current_state USING btree (agent_id, file_uid);


--
-- Name: idx_fim_current_state_agent_path; Type: INDEX; Schema: fim; Owner: -
--

CREATE INDEX idx_fim_current_state_agent_path ON fim.fim_current_state USING btree (agent_id, path);


--
-- Name: idx_fim_current_state_chunk_hashes_gin; Type: INDEX; Schema: fim; Owner: -
--

CREATE INDEX idx_fim_current_state_chunk_hashes_gin ON fim.fim_current_state USING gin (chunk_hashes_json);


--
-- Name: idx_fim_current_state_combined_hash; Type: INDEX; Schema: fim; Owner: -
--

CREATE INDEX idx_fim_current_state_combined_hash ON fim.fim_current_state USING btree (combined_hash);


--
-- Name: idx_fim_current_state_integrity; Type: INDEX; Schema: fim; Owner: -
--

CREATE INDEX idx_fim_current_state_integrity ON fim.fim_current_state USING btree (integrity);


--
-- Name: idx_fim_current_state_last_event_time; Type: INDEX; Schema: fim; Owner: -
--

CREATE INDEX idx_fim_current_state_last_event_time ON fim.fim_current_state USING btree (last_event_time DESC);


--
-- Name: idx_fim_current_state_snapshot_gin; Type: INDEX; Schema: fim; Owner: -
--

CREATE INDEX idx_fim_current_state_snapshot_gin ON fim.fim_current_state USING gin (snapshot_json);


--
-- Name: idx_fim_events_agent_file_uid; Type: INDEX; Schema: fim; Owner: -
--

CREATE INDEX idx_fim_events_agent_file_uid ON fim.fim_events USING btree (agent_id, file_uid);


--
-- Name: idx_fim_events_agent_id; Type: INDEX; Schema: fim; Owner: -
--

CREATE INDEX idx_fim_events_agent_id ON fim.fim_events USING btree (agent_id);


--
-- Name: idx_fim_events_chunk_diff_gin; Type: INDEX; Schema: fim; Owner: -
--

CREATE INDEX idx_fim_events_chunk_diff_gin ON fim.fim_events USING gin (chunk_diff_json);


--
-- Name: idx_fim_events_chunk_hashes_gin; Type: INDEX; Schema: fim; Owner: -
--

CREATE INDEX idx_fim_events_chunk_hashes_gin ON fim.fim_events USING gin (chunk_hashes_json);


--
-- Name: idx_fim_events_combined_hash; Type: INDEX; Schema: fim; Owner: -
--

CREATE INDEX idx_fim_events_combined_hash ON fim.fim_events USING btree (combined_hash);


--
-- Name: idx_fim_events_content_hash; Type: INDEX; Schema: fim; Owner: -
--

CREATE INDEX idx_fim_events_content_hash ON fim.fim_events USING btree (content_hash);


--
-- Name: idx_fim_events_endpoint; Type: INDEX; Schema: fim; Owner: -
--

CREATE INDEX idx_fim_events_endpoint ON fim.fim_events USING btree (endpoint);


--
-- Name: idx_fim_events_event_type; Type: INDEX; Schema: fim; Owner: -
--

CREATE INDEX idx_fim_events_event_type ON fim.fim_events USING btree (event_type);


--
-- Name: idx_fim_events_file_uid; Type: INDEX; Schema: fim; Owner: -
--

CREATE INDEX idx_fim_events_file_uid ON fim.fim_events USING btree (file_uid);


--
-- Name: idx_fim_events_hostname; Type: INDEX; Schema: fim; Owner: -
--

CREATE INDEX idx_fim_events_hostname ON fim.fim_events USING btree (hostname);


--
-- Name: idx_fim_events_old_new_path; Type: INDEX; Schema: fim; Owner: -
--

CREATE INDEX idx_fim_events_old_new_path ON fim.fim_events USING btree (old_path, new_path);


--
-- Name: idx_fim_events_path; Type: INDEX; Schema: fim; Owner: -
--

CREATE INDEX idx_fim_events_path ON fim.fim_events USING btree (path);


--
-- Name: idx_fim_events_policy_violation; Type: INDEX; Schema: fim; Owner: -
--

CREATE INDEX idx_fim_events_policy_violation ON fim.fim_events USING btree (policy_violation) WHERE (policy_violation = true);


--
-- Name: idx_fim_events_severity; Type: INDEX; Schema: fim; Owner: -
--

CREATE INDEX idx_fim_events_severity ON fim.fim_events USING btree (severity);


--
-- Name: idx_fim_events_snapshot_gin; Type: INDEX; Schema: fim; Owner: -
--

CREATE INDEX idx_fim_events_snapshot_gin ON fim.fim_events USING gin (snapshot_json);


--
-- Name: idx_fim_events_time; Type: INDEX; Schema: fim; Owner: -
--

CREATE INDEX idx_fim_events_time ON fim.fim_events USING btree (event_time DESC);


--
-- Name: idx_sysmon_events_code; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_sysmon_events_code ON public.sysmon_events USING btree (event_code);


--
-- Name: idx_sysmon_events_host; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_sysmon_events_host ON public.sysmon_events USING btree (host);


--
-- Name: idx_sysmon_events_ts; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_sysmon_events_ts ON public.sysmon_events USING btree (event_timestamp);


--
-- Name: fim_events trg_apply_integrity_policy; Type: TRIGGER; Schema: fim; Owner: -
--

CREATE TRIGGER trg_apply_integrity_policy BEFORE INSERT ON fim.fim_events FOR EACH ROW EXECUTE FUNCTION fim.apply_integrity_policy();


--
-- Name: fim_events trg_sync_current_state; Type: TRIGGER; Schema: fim; Owner: -
--

CREATE TRIGGER trg_sync_current_state AFTER INSERT ON fim.fim_events FOR EACH ROW EXECUTE FUNCTION fim.sync_current_state();


--
-- Name: alert_notifications alert_notifications_event_id_fkey; Type: FK CONSTRAINT; Schema: fim; Owner: -
--

ALTER TABLE ONLY fim.alert_notifications
    ADD CONSTRAINT alert_notifications_event_id_fkey FOREIGN KEY (event_id) REFERENCES fim.fim_events(id) ON DELETE CASCADE;


--
-- Name: fim_current_state fim_current_state_last_event_id_fkey; Type: FK CONSTRAINT; Schema: fim; Owner: -
--

ALTER TABLE ONLY fim.fim_current_state
    ADD CONSTRAINT fim_current_state_last_event_id_fkey FOREIGN KEY (last_event_id) REFERENCES fim.fim_events(id) ON DELETE CASCADE;


--
-- PostgreSQL database dump complete
--

\unrestrict ebWSAHo30PIndxWbglip5tfMoocehqKL1z7OGNG02uVCbbdHpn0EbQBxbEBVbZS

