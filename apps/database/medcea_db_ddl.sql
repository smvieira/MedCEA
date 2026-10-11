--
-- PostgreSQL database dump
--

\restrict 7rmBgPZzF3G0lEacS7r0sASHMTy3HOL0PDECnKChymSdto396bdhbAPAqqsCIlo

-- Dumped from database version 18.3
-- Dumped by pg_dump version 18.3

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET transaction_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: medcea; Type: SCHEMA; Schema: -; Owner: postgres
--

CREATE SCHEMA medcea;


ALTER SCHEMA medcea OWNER TO postgres;

--
-- Name: is_active; Type: DOMAIN; Schema: medcea; Owner: postgres
--

CREATE DOMAIN medcea.is_active AS character varying
	CONSTRAINT is_active_check CHECK ((((VALUE)::text ~ 'Y'::text) OR ((VALUE)::text ~ 'N'::text)));


ALTER DOMAIN medcea.is_active OWNER TO postgres;

--
-- Name: light_types; Type: DOMAIN; Schema: medcea; Owner: postgres
--

CREATE DOMAIN medcea.light_types AS character varying
	CONSTRAINT light_types_check CHECK ((((VALUE)::text ~ 'UV'::text) OR ((VALUE)::text ~ 'BLUE'::text) OR ((VALUE)::text ~ 'RED'::text) OR ((VALUE)::text ~ 'DARK'::text)));


ALTER DOMAIN medcea.light_types OWNER TO postgres;

--
-- Name: msg_type; Type: DOMAIN; Schema: medcea; Owner: postgres
--

CREATE DOMAIN medcea.msg_type AS character varying(2)
	CONSTRAINT msg_type_check CHECK ((((VALUE)::text ~ 'AP'::text) OR ((VALUE)::text ~ 'CT'::text) OR ((VALUE)::text ~ 'SP'::text)));


ALTER DOMAIN medcea.msg_type OWNER TO postgres;

--
-- Name: run_status; Type: DOMAIN; Schema: medcea; Owner: postgres
--

CREATE DOMAIN medcea.run_status AS character varying
	CONSTRAINT run_status_check CHECK ((((VALUE)::text ~ 'F'::text) OR ((VALUE)::text ~ 'R'::text) OR ((VALUE)::text ~ 'S'::text) OR ((VALUE)::text ~ 'C'::text)));


ALTER DOMAIN medcea.run_status OWNER TO postgres;

--
-- Name: unit_type; Type: DOMAIN; Schema: medcea; Owner: postgres
--

CREATE DOMAIN medcea.unit_type AS character varying(10)
	CONSTRAINT unit_type_check CHECK ((((VALUE)::text ~ 'Greens'::text) OR ((VALUE)::text ~ 'Mushrooms'::text) OR ((VALUE)::text ~ 'Other'::text)));


ALTER DOMAIN medcea.unit_type OWNER TO postgres;

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: backup_remote_to_insert_measurement; Type: TABLE; Schema: medcea; Owner: postgres
--

CREATE TABLE medcea.backup_remote_to_insert_measurement (
    measure_timestamp timestamp with time zone,
    device_id character varying,
    device_dns character varying,
    msg_type medcea.msg_type,
    msg json,
    "timestamp" timestamp with time zone
);


ALTER TABLE medcea.backup_remote_to_insert_measurement OWNER TO postgres;

--
-- Name: cea_location; Type: TABLE; Schema: medcea; Owner: postgres
--

CREATE TABLE medcea.cea_location (
    location_id integer NOT NULL,
    name character varying(255) NOT NULL,
    address character varying(255),
    latitude numeric,
    longitude numeric,
    contact_person character varying(255),
    contact_info character varying(255),
    description text,
    is_active medcea.is_active
);


ALTER TABLE medcea.cea_location OWNER TO postgres;

--
-- Name: TABLE cea_location; Type: COMMENT; Schema: medcea; Owner: postgres
--

COMMENT ON TABLE medcea.cea_location IS 'Represents the facility where growing areas are located.';


--
-- Name: COLUMN cea_location.location_id; Type: COMMENT; Schema: medcea; Owner: postgres
--

COMMENT ON COLUMN medcea.cea_location.location_id IS 'Unique identifier for the location.';


--
-- Name: COLUMN cea_location.name; Type: COMMENT; Schema: medcea; Owner: postgres
--

COMMENT ON COLUMN medcea.cea_location.name IS 'Name of the farm or facility.';


--
-- Name: COLUMN cea_location.address; Type: COMMENT; Schema: medcea; Owner: postgres
--

COMMENT ON COLUMN medcea.cea_location.address IS 'Physical address of the location.';


--
-- Name: COLUMN cea_location.latitude; Type: COMMENT; Schema: medcea; Owner: postgres
--

COMMENT ON COLUMN medcea.cea_location.latitude IS 'Latitude coordinate of the location.';


--
-- Name: COLUMN cea_location.longitude; Type: COMMENT; Schema: medcea; Owner: postgres
--

COMMENT ON COLUMN medcea.cea_location.longitude IS 'Longitude coordinate of the location.';


--
-- Name: COLUMN cea_location.contact_person; Type: COMMENT; Schema: medcea; Owner: postgres
--

COMMENT ON COLUMN medcea.cea_location.contact_person IS 'Contact person at the location.';


--
-- Name: COLUMN cea_location.contact_info; Type: COMMENT; Schema: medcea; Owner: postgres
--

COMMENT ON COLUMN medcea.cea_location.contact_info IS 'Contact information (phone, email) for the location.';


--
-- Name: COLUMN cea_location.description; Type: COMMENT; Schema: medcea; Owner: postgres
--

COMMENT ON COLUMN medcea.cea_location.description IS 'Description of the facility.';


--
-- Name: cea_location_location_id_seq; Type: SEQUENCE; Schema: medcea; Owner: postgres
--

CREATE SEQUENCE medcea.cea_location_location_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE medcea.cea_location_location_id_seq OWNER TO postgres;

--
-- Name: cea_location_location_id_seq; Type: SEQUENCE OWNED BY; Schema: medcea; Owner: postgres
--

ALTER SEQUENCE medcea.cea_location_location_id_seq OWNED BY medcea.cea_location.location_id;


--
-- Name: cea_unit; Type: TABLE; Schema: medcea; Owner: postgres
--

CREATE TABLE medcea.cea_unit (
    unit_id integer NOT NULL,
    unit_type medcea.unit_type NOT NULL,
    description character varying,
    location_id integer NOT NULL,
    area double precision,
    height double precision,
    "timestamp" timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    is_active medcea.is_active NOT NULL,
    unit_code character varying(10) NOT NULL
);


ALTER TABLE medcea.cea_unit OWNER TO postgres;

--
-- Name: COLUMN cea_unit.unit_id; Type: COMMENT; Schema: medcea; Owner: postgres
--

COMMENT ON COLUMN medcea.cea_unit.unit_id IS 'Production unit identifier.';


--
-- Name: COLUMN cea_unit.area; Type: COMMENT; Schema: medcea; Owner: postgres
--

COMMENT ON COLUMN medcea.cea_unit.area IS 'facility''s production area. Used to calculate volume.';


--
-- Name: COLUMN cea_unit.height; Type: COMMENT; Schema: medcea; Owner: postgres
--

COMMENT ON COLUMN medcea.cea_unit.height IS 'facility''s production height. Used to calculate facility volume.';


--
-- Name: COLUMN cea_unit."timestamp"; Type: COMMENT; Schema: medcea; Owner: postgres
--

COMMENT ON COLUMN medcea.cea_unit."timestamp" IS 'Record creation timestamp';


--
-- Name: COLUMN cea_unit.unit_code; Type: COMMENT; Schema: medcea; Owner: postgres
--

COMMENT ON COLUMN medcea.cea_unit.unit_code IS 'Unit code, used to handle backend processes (order to be changed)';


--
-- Name: cea_unit_unit_id_seq; Type: SEQUENCE; Schema: medcea; Owner: postgres
--

CREATE SEQUENCE medcea.cea_unit_unit_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE medcea.cea_unit_unit_id_seq OWNER TO postgres;

--
-- Name: cea_unit_unit_id_seq; Type: SEQUENCE OWNED BY; Schema: medcea; Owner: postgres
--

ALTER SEQUENCE medcea.cea_unit_unit_id_seq OWNED BY medcea.cea_unit.unit_id;


--
-- Name: cea_zone_zone_id_seq; Type: SEQUENCE; Schema: medcea; Owner: postgres
--

CREATE SEQUENCE medcea.cea_zone_zone_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE medcea.cea_zone_zone_id_seq OWNER TO postgres;

--
-- Name: cea_zone; Type: TABLE; Schema: medcea; Owner: postgres
--

CREATE TABLE medcea.cea_zone (
    unit_id integer NOT NULL,
    zone_id integer DEFAULT nextval('medcea.cea_zone_zone_id_seq'::regclass) NOT NULL,
    zone_code character varying NOT NULL,
    zone_description character varying,
    timestamp_cre timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    is_active medcea.is_active NOT NULL
);


ALTER TABLE medcea.cea_zone OWNER TO postgres;

--
-- Name: component; Type: TABLE; Schema: medcea; Owner: postgres
--

CREATE TABLE medcea.component (
    component_id integer NOT NULL,
    device_id integer NOT NULL,
    component_type character varying(8),
    model character varying(255),
    manufacturer character varying(255),
    parameters json,
    is_active medcea.is_active DEFAULT 'Y'::character varying,
    timestamp_cre timestamp without time zone DEFAULT CURRENT_TIMESTAMP
);


ALTER TABLE medcea.component OWNER TO postgres;

--
-- Name: TABLE component; Type: COMMENT; Schema: medcea; Owner: postgres
--

COMMENT ON TABLE medcea.component IS 'Represents the Component (sensor or actuator) installed in IoT devices used in the CEA system.';


--
-- Name: COLUMN component.component_id; Type: COMMENT; Schema: medcea; Owner: postgres
--

COMMENT ON COLUMN medcea.component.component_id IS 'Component identifier';


--
-- Name: COLUMN component.device_id; Type: COMMENT; Schema: medcea; Owner: postgres
--

COMMENT ON COLUMN medcea.component.device_id IS 'Unique identifier for the IoT device with in CEA environment e.g same as dns name.';


--
-- Name: COLUMN component.component_type; Type: COMMENT; Schema: medcea; Owner: postgres
--

COMMENT ON COLUMN medcea.component.component_type IS 'Type of component use by the device (e.g., CO2 sensor, heater actuator, etc).';


--
-- Name: COLUMN component.model; Type: COMMENT; Schema: medcea; Owner: postgres
--

COMMENT ON COLUMN medcea.component.model IS 'Model of the component.';


--
-- Name: COLUMN component.manufacturer; Type: COMMENT; Schema: medcea; Owner: postgres
--

COMMENT ON COLUMN medcea.component.manufacturer IS 'Manufacturer of the device.';


--
-- Name: COLUMN component.parameters; Type: COMMENT; Schema: medcea; Owner: postgres
--

COMMENT ON COLUMN medcea.component.parameters IS 'Parameters implemented by the component.';


--
-- Name: COLUMN component.is_active; Type: COMMENT; Schema: medcea; Owner: postgres
--

COMMENT ON COLUMN medcea.component.is_active IS 'Current status of the device (e.g., Y if Active,  No if Inactive).';


--
-- Name: component_component_id_seq; Type: SEQUENCE; Schema: medcea; Owner: postgres
--

CREATE SEQUENCE medcea.component_component_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE medcea.component_component_id_seq OWNER TO postgres;

--
-- Name: component_component_id_seq; Type: SEQUENCE OWNED BY; Schema: medcea; Owner: postgres
--

ALTER SEQUENCE medcea.component_component_id_seq OWNED BY medcea.component.component_id;


--
-- Name: databasechangeloglock; Type: TABLE; Schema: medcea; Owner: postgres
--

CREATE TABLE medcea.databasechangeloglock (
    id integer NOT NULL,
    locked boolean NOT NULL,
    lockgranted timestamp without time zone,
    lockedby character varying(255)
);


ALTER TABLE medcea.databasechangeloglock OWNER TO postgres;

--
-- Name: device; Type: TABLE; Schema: medcea; Owner: postgres
--

CREATE TABLE medcea.device (
    device_id integer NOT NULL,
    zone_id integer,
    device_type character varying(255) NOT NULL,
    model character varying(255),
    manufacturer character varying(255),
    serial_number character varying(255) NOT NULL,
    connection_type character varying(255) DEFAULT 'WiFi'::character varying NOT NULL,
    dns_name character varying(255) NOT NULL,
    installation_date date DEFAULT CURRENT_TIMESTAMP,
    is_active medcea.is_active DEFAULT 'Y'::character varying
);


ALTER TABLE medcea.device OWNER TO postgres;

--
-- Name: TABLE device; Type: COMMENT; Schema: medcea; Owner: postgres
--

COMMENT ON TABLE medcea.device IS 'Represents an IoT device used in the CEA system.';


--
-- Name: COLUMN device.device_id; Type: COMMENT; Schema: medcea; Owner: postgres
--

COMMENT ON COLUMN medcea.device.device_id IS 'Unique identifier for the IoT device with in CEA environment e.g same as dns name.';


--
-- Name: COLUMN device.zone_id; Type: COMMENT; Schema: medcea; Owner: postgres
--

COMMENT ON COLUMN medcea.device.zone_id IS 'Production zone of identifier';


--
-- Name: COLUMN device.device_type; Type: COMMENT; Schema: medcea; Owner: postgres
--

COMMENT ON COLUMN medcea.device.device_type IS 'Type of device (e.g., Control, Sense or Both).';


--
-- Name: COLUMN device.model; Type: COMMENT; Schema: medcea; Owner: postgres
--

COMMENT ON COLUMN medcea.device.model IS 'Model of the device.';


--
-- Name: COLUMN device.manufacturer; Type: COMMENT; Schema: medcea; Owner: postgres
--

COMMENT ON COLUMN medcea.device.manufacturer IS 'Manufacturer of the device.';


--
-- Name: COLUMN device.serial_number; Type: COMMENT; Schema: medcea; Owner: postgres
--

COMMENT ON COLUMN medcea.device.serial_number IS 'Unique serial number of the device.';


--
-- Name: COLUMN device.connection_type; Type: COMMENT; Schema: medcea; Owner: postgres
--

COMMENT ON COLUMN medcea.device.connection_type IS 'Type of connection used by the device (e.g., Wi-Fi, LoRaWAN).';


--
-- Name: COLUMN device.dns_name; Type: COMMENT; Schema: medcea; Owner: postgres
--

COMMENT ON COLUMN medcea.device.dns_name IS 'Dns or IP of the device.';


--
-- Name: COLUMN device.installation_date; Type: COMMENT; Schema: medcea; Owner: postgres
--

COMMENT ON COLUMN medcea.device.installation_date IS 'Date of device installation.';


--
-- Name: COLUMN device.is_active; Type: COMMENT; Schema: medcea; Owner: postgres
--

COMMENT ON COLUMN medcea.device.is_active IS 'Current status of the device (e.g., Y for Active, N for Inactive).';


--
-- Name: device_device_id_seq; Type: SEQUENCE; Schema: medcea; Owner: postgres
--

CREATE SEQUENCE medcea.device_device_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE medcea.device_device_id_seq OWNER TO postgres;

--
-- Name: device_device_id_seq; Type: SEQUENCE OWNED BY; Schema: medcea; Owner: postgres
--

ALTER SEQUENCE medcea.device_device_id_seq OWNED BY medcea.device.device_id;


--
-- Name: measurement; Type: TABLE; Schema: medcea; Owner: postgres
--

CREATE TABLE medcea.measurement (
    measure_timestamp timestamp with time zone NOT NULL,
    device_id character varying NOT NULL,
    device_dns character varying NOT NULL,
    msg_type medcea.msg_type NOT NULL,
    msg json NOT NULL,
    "timestamp" timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL
);


ALTER TABLE medcea.measurement OWNER TO postgres;

--
-- Name: COLUMN measurement.device_dns; Type: COMMENT; Schema: medcea; Owner: postgres
--

COMMENT ON COLUMN medcea.measurement.device_dns IS 'Unique identifier for the IoT device with in CEA environment (e.g dns name) .';


--
-- Name: msg_actual_points; Type: VIEW; Schema: medcea; Owner: postgres
--

CREATE VIEW medcea.msg_actual_points AS
 SELECT (msg ->> 'unit_code'::text) AS unit_code,
    (msg ->> 'zone_code'::text) AS zone_code,
    (msg ->> 'timestamp'::text) AS measure_timestamp,
    (msg ->> 'msg_type'::text) AS msg_type,
    (msg ->> 'tag'::text) AS tag,
    (msg ->> 'device_dns'::text) AS device_dns,
    (msg ->> 'value'::text) AS value,
    (msg ->> 'UoM'::text) AS uom,
    (msg ->> 'device_id'::text) AS device_id,
    "timestamp" AS record_timestamp,
    msg
   FROM medcea.measurement
  WHERE ((msg_type)::text = 'AP'::text);


ALTER VIEW medcea.msg_actual_points OWNER TO postgres;

--
-- Name: msg_controls; Type: VIEW; Schema: medcea; Owner: postgres
--

CREATE VIEW medcea.msg_controls AS
 SELECT (measurement.msg ->> 'unit_code'::text) AS unit_code,
    (measurement.msg ->> 'zone_code'::text) AS unit_zone,
    (measurement.msg ->> 'timestamp'::text) AS measure_timestamp,
    (measurement.msg ->> 'msg_type'::text) AS msg_type,
    (measurement.msg ->> 'device_id'::text) AS device_id,
    json_each.key AS tag,
    (json_each.value)::text AS value,
    measurement.msg
   FROM medcea.measurement,
    LATERAL json_each(measurement.msg) json_each(key, value)
  WHERE (((measurement.msg_type)::text = 'CT'::text) AND (json_each.key <> ALL (ARRAY['unit_code'::text, 'unit_zone'::text, 'timestamp'::text, 'msg_type'::text, 'device_dns'::text, 'device_id'::text])));


ALTER VIEW medcea.msg_controls OWNER TO postgres;

--
-- Name: msg_set_points; Type: VIEW; Schema: medcea; Owner: postgres
--

CREATE VIEW medcea.msg_set_points AS
 SELECT (msg ->> 'unit_code'::text) AS unit_code,
    (msg ->> 'unit_zone'::text) AS unit_zone,
    (msg ->> 'timestamp'::text) AS measure_timestamp,
    (msg ->> 'msg_type'::text) AS msg_type,
    (msg ->> 'tag'::text) AS tag,
    (msg ->> 'device_dns'::text) AS device_dns,
    (msg ->> 'value'::text) AS value,
    (msg ->> 'device_id'::text) AS device_id,
    "timestamp" AS record_timestamp,
    msg
   FROM medcea.measurement
  WHERE ((msg_type)::text = 'SP'::text);


ALTER VIEW medcea.msg_set_points OWNER TO postgres;

--
-- Name: recipe_recipe_id_seq; Type: SEQUENCE; Schema: medcea; Owner: postgres
--

CREATE SEQUENCE medcea.recipe_recipe_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE medcea.recipe_recipe_id_seq OWNER TO postgres;

--
-- Name: recipe; Type: TABLE; Schema: medcea; Owner: postgres
--

CREATE TABLE medcea.recipe (
    recipe_id integer DEFAULT nextval('medcea.recipe_recipe_id_seq'::regclass) NOT NULL,
    recipe_name character varying NOT NULL,
    recipe_description character varying,
    timestamp_cre timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    timestamp_upd timestamp with time zone,
    is_active character varying DEFAULT 'Y'::character varying NOT NULL
);


ALTER TABLE medcea.recipe OWNER TO postgres;

--
-- Name: recipe_line; Type: TABLE; Schema: medcea; Owner: postgres
--

CREATE TABLE medcea.recipe_line (
    recipe_id integer NOT NULL,
    recipe_item_seq_id integer NOT NULL,
    recipe_item_seq_name character varying NOT NULL,
    cycle_number integer NOT NULL,
    air_temperature_lower_limit integer NOT NULL,
    air_temperature_upper_limit integer NOT NULL,
    light_type medcea.light_types NOT NULL,
    light_on_minutes integer NOT NULL,
    light_off_minutes integer NOT NULL,
    co2_lower_limit integer NOT NULL,
    co2_upper_limit integer NOT NULL,
    hr_lower_limit integer NOT NULL,
    hr_upper_limit integer NOT NULL,
    timestamp_cre timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    timestamp_upd timestamp with time zone,
    substrate_temperature_lower_limit integer,
    substrate_temperature_upper_limit integer,
    notes character varying
);


ALTER TABLE medcea.recipe_line OWNER TO postgres;

--
-- Name: recipe_line_cycle_run; Type: TABLE; Schema: medcea; Owner: postgres
--

CREATE TABLE medcea.recipe_line_cycle_run (
    recipe_line_cycle_run_id integer NOT NULL,
    recipe_run_id integer NOT NULL,
    recipe_id integer NOT NULL,
    recipe_item_seq_id integer NOT NULL,
    recipe_item_seq_cycle_num integer NOT NULL,
    recipe_line_seq_cycle_run_start timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    recipe_line_seq_cycle_run_end timestamp with time zone,
    recipe_line_cycle_run_status medcea.run_status NOT NULL,
    run_params json,
    timestamp_cre timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    timestamp_upd timestamp with time zone
);


ALTER TABLE medcea.recipe_line_cycle_run OWNER TO postgres;

--
-- Name: recipe_line_cycle_run_recipe_line_cycle_run_id_seq; Type: SEQUENCE; Schema: medcea; Owner: postgres
--

CREATE SEQUENCE medcea.recipe_line_cycle_run_recipe_line_cycle_run_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE medcea.recipe_line_cycle_run_recipe_line_cycle_run_id_seq OWNER TO postgres;

--
-- Name: recipe_line_cycle_run_recipe_line_cycle_run_id_seq; Type: SEQUENCE OWNED BY; Schema: medcea; Owner: postgres
--

ALTER SEQUENCE medcea.recipe_line_cycle_run_recipe_line_cycle_run_id_seq OWNED BY medcea.recipe_line_cycle_run.recipe_line_cycle_run_id;


--
-- Name: recipe_run; Type: TABLE; Schema: medcea; Owner: postgres
--

CREATE TABLE medcea.recipe_run (
    recipe_run_id integer NOT NULL,
    recipe_id integer NOT NULL,
    unit_id integer NOT NULL,
    recipe_run_start timestamp with time zone NOT NULL,
    recipe_run_end timestamp with time zone,
    timestamp_cre timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    timestamp_upd timestamp with time zone,
    recipe_run_status medcea.run_status NOT NULL,
    is_active medcea.is_active NOT NULL
);


ALTER TABLE medcea.recipe_run OWNER TO postgres;

--
-- Name: recipe_run_recipe_run_id_seq; Type: SEQUENCE; Schema: medcea; Owner: postgres
--

CREATE SEQUENCE medcea.recipe_run_recipe_run_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE medcea.recipe_run_recipe_run_id_seq OWNER TO postgres;

--
-- Name: recipe_run_recipe_run_id_seq; Type: SEQUENCE OWNED BY; Schema: medcea; Owner: postgres
--

ALTER SEQUENCE medcea.recipe_run_recipe_run_id_seq OWNED BY medcea.recipe_run.recipe_run_id;


--
-- Name: recipe_unit_permission; Type: TABLE; Schema: medcea; Owner: postgres
--

CREATE TABLE medcea.recipe_unit_permission (
    recipe_id integer NOT NULL,
    unit_id integer NOT NULL,
    allowed boolean DEFAULT true NOT NULL
);


ALTER TABLE medcea.recipe_unit_permission OWNER TO postgres;

--
-- Name: run_history; Type: VIEW; Schema: medcea; Owner: postgres
--

CREATE VIEW medcea.run_history AS
 SELECT r.recipe_id,
    r.recipe_name,
    r.recipe_description,
    rl.recipe_item_seq_name,
    rl.recipe_item_seq_id,
    rl.cycle_number,
    rlcr.recipe_item_seq_cycle_num,
    rlcr.recipe_line_seq_cycle_run_start,
    COALESCE(rlcr.recipe_line_seq_cycle_run_end, rlcr.recipe_line_seq_cycle_run_start) AS recipe_line_seq_cycle_run_end,
    rl.air_temperature_lower_limit,
    rl.air_temperature_upper_limit,
    rl.light_type,
    rl.light_on_minutes,
    rl.light_off_minutes,
    rl.co2_lower_limit,
    rl.co2_upper_limit,
    rl.hr_lower_limit,
    rl.hr_upper_limit,
    rl.substrate_temperature_lower_limit,
    rl.substrate_temperature_upper_limit,
    rr.recipe_run_id,
    rr.unit_id
   FROM (((medcea.recipe r
     JOIN medcea.recipe_line rl ON ((r.recipe_id = rl.recipe_id)))
     JOIN medcea.recipe_run rr ON ((rr.recipe_id = r.recipe_id)))
     LEFT JOIN medcea.recipe_line_cycle_run rlcr ON (((rr.recipe_run_id = rlcr.recipe_run_id) AND (rl.recipe_id = rlcr.recipe_id) AND (rl.recipe_item_seq_id = rlcr.recipe_item_seq_id))))
  ORDER BY rl.recipe_id, rl.recipe_item_seq_id, rlcr.recipe_item_seq_cycle_num;


ALTER VIEW medcea.run_history OWNER TO postgres;

--
-- Name: run_watch; Type: VIEW; Schema: medcea; Owner: postgres
--

CREATE VIEW medcea.run_watch AS
 SELECT r.recipe_id,
    r.recipe_name,
    r.recipe_description,
    rl.recipe_item_seq_name,
    rl.recipe_item_seq_id,
    rl.cycle_number,
    rlcr.recipe_item_seq_cycle_num,
    rlcr.recipe_line_seq_cycle_run_start,
    rlcr.recipe_line_seq_cycle_run_end,
    rl.air_temperature_lower_limit,
    rl.air_temperature_upper_limit,
    rl.light_type,
    rl.light_on_minutes,
    rl.light_off_minutes,
    rl.co2_lower_limit,
    rl.co2_upper_limit,
    rl.hr_lower_limit,
    rl.hr_upper_limit,
    rl.substrate_temperature_lower_limit,
    rl.substrate_temperature_upper_limit,
    rr.recipe_run_id,
    rr.unit_id
   FROM (((medcea.recipe r
     JOIN medcea.recipe_line rl ON ((r.recipe_id = rl.recipe_id)))
     JOIN medcea.recipe_run rr ON ((rr.recipe_id = r.recipe_id)))
     LEFT JOIN medcea.recipe_line_cycle_run rlcr ON (((rr.recipe_run_id = rlcr.recipe_run_id) AND (rl.recipe_id = rlcr.recipe_id) AND (rl.recipe_item_seq_id = rlcr.recipe_item_seq_id))))
  WHERE ((rr.recipe_run_status)::text <> 'C'::text)
  ORDER BY rl.recipe_id, rl.recipe_item_seq_id, rlcr.recipe_item_seq_cycle_num;


ALTER VIEW medcea.run_watch OWNER TO postgres;

--
-- Name: v_ap_measurements; Type: VIEW; Schema: medcea; Owner: postgres
--

CREATE VIEW medcea.v_ap_measurements AS
 SELECT measure_timestamp,
    device_id,
    device_dns,
    msg_type,
    "timestamp" AS db_timestamp,
    (msg ->> 'unit_code'::text) AS unit_code,
    (msg ->> 'zone_code'::text) AS zone_code,
    (msg ->> 'tag'::text) AS tag,
    ((msg ->> 'value'::text))::numeric AS value,
    (msg ->> 'UoM'::text) AS unit_of_measurement,
    ((msg ->> 'timestamp'::text))::timestamp without time zone AS message_timestamp,
    msg
   FROM medcea.measurement
  WHERE ((msg_type)::text = 'AP'::text);


ALTER VIEW medcea.v_ap_measurements OWNER TO postgres;

--
-- Name: v_ct_measurements; Type: VIEW; Schema: medcea; Owner: postgres
--

CREATE VIEW medcea.v_ct_measurements AS
 SELECT measure_timestamp,
    device_id,
    device_dns,
    msg_type,
    "timestamp" AS db_timestamp,
    (msg ->> 'unit_code'::text) AS unit_code,
    (msg ->> 'zone_code'::text) AS zone_code,
    (msg ->> 'tag'::text) AS tag,
    (msg ->> 'command'::text) AS command,
    ((msg ->> 'timestamp'::text))::timestamp without time zone AS message_timestamp,
    msg
   FROM medcea.measurement
  WHERE ((msg_type)::text = 'CT'::text);


ALTER VIEW medcea.v_ct_measurements OWNER TO postgres;

--
-- Name: v_sp_measurements; Type: VIEW; Schema: medcea; Owner: postgres
--

CREATE VIEW medcea.v_sp_measurements AS
 SELECT measure_timestamp,
    device_id,
    device_dns,
    msg_type,
    "timestamp" AS db_timestamp,
    (msg ->> 'unit_code'::text) AS unit_code,
    (msg ->> 'zone_code'::text) AS zone_code,
    (msg ->> 'tag'::text) AS tag,
    ((msg ->> 'pin'::text))::integer AS pin,
    ((msg ->> 'value'::text))::integer AS value,
    ((msg ->> 'timestamp'::text))::timestamp without time zone AS message_timestamp,
    msg
   FROM medcea.measurement
  WHERE ((msg_type)::text = 'SP'::text);


ALTER VIEW medcea.v_sp_measurements OWNER TO postgres;

--
-- Name: cea_location location_id; Type: DEFAULT; Schema: medcea; Owner: postgres
--

ALTER TABLE ONLY medcea.cea_location ALTER COLUMN location_id SET DEFAULT nextval('medcea.cea_location_location_id_seq'::regclass);


--
-- Name: cea_unit unit_id; Type: DEFAULT; Schema: medcea; Owner: postgres
--

ALTER TABLE ONLY medcea.cea_unit ALTER COLUMN unit_id SET DEFAULT nextval('medcea.cea_unit_unit_id_seq'::regclass);


--
-- Name: component component_id; Type: DEFAULT; Schema: medcea; Owner: postgres
--

ALTER TABLE ONLY medcea.component ALTER COLUMN component_id SET DEFAULT nextval('medcea.component_component_id_seq'::regclass);


--
-- Name: device device_id; Type: DEFAULT; Schema: medcea; Owner: postgres
--

ALTER TABLE ONLY medcea.device ALTER COLUMN device_id SET DEFAULT nextval('medcea.device_device_id_seq'::regclass);


--
-- Name: recipe_line_cycle_run recipe_line_cycle_run_id; Type: DEFAULT; Schema: medcea; Owner: postgres
--

ALTER TABLE ONLY medcea.recipe_line_cycle_run ALTER COLUMN recipe_line_cycle_run_id SET DEFAULT nextval('medcea.recipe_line_cycle_run_recipe_line_cycle_run_id_seq'::regclass);


--
-- Name: recipe_run recipe_run_id; Type: DEFAULT; Schema: medcea; Owner: postgres
--

ALTER TABLE ONLY medcea.recipe_run ALTER COLUMN recipe_run_id SET DEFAULT nextval('medcea.recipe_run_recipe_run_id_seq'::regclass);


--
-- Name: device cea_device_pkey; Type: CONSTRAINT; Schema: medcea; Owner: postgres
--

ALTER TABLE ONLY medcea.device
    ADD CONSTRAINT cea_device_pkey PRIMARY KEY (device_id);


--
-- Name: cea_location cea_location_pkey; Type: CONSTRAINT; Schema: medcea; Owner: postgres
--

ALTER TABLE ONLY medcea.cea_location
    ADD CONSTRAINT cea_location_pkey PRIMARY KEY (location_id);


--
-- Name: cea_zone cea_zone_pkey; Type: CONSTRAINT; Schema: medcea; Owner: postgres
--

ALTER TABLE ONLY medcea.cea_zone
    ADD CONSTRAINT cea_zone_pkey PRIMARY KEY (zone_id);


--
-- Name: component component_pkey; Type: CONSTRAINT; Schema: medcea; Owner: postgres
--

ALTER TABLE ONLY medcea.component
    ADD CONSTRAINT component_pkey PRIMARY KEY (component_id);


--
-- Name: databasechangeloglock databasechangeloglock_pkey; Type: CONSTRAINT; Schema: medcea; Owner: postgres
--

ALTER TABLE ONLY medcea.databasechangeloglock
    ADD CONSTRAINT databasechangeloglock_pkey PRIMARY KEY (id);


--
-- Name: device dns_name_uk; Type: CONSTRAINT; Schema: medcea; Owner: postgres
--

ALTER TABLE ONLY medcea.device
    ADD CONSTRAINT dns_name_uk UNIQUE (dns_name);


--
-- Name: recipe_line_cycle_run recipe_line_cycle_run_pkey; Type: CONSTRAINT; Schema: medcea; Owner: postgres
--

ALTER TABLE ONLY medcea.recipe_line_cycle_run
    ADD CONSTRAINT recipe_line_cycle_run_pkey PRIMARY KEY (recipe_line_cycle_run_id);


--
-- Name: recipe_line_cycle_run recipe_line_cycle_run_uk; Type: CONSTRAINT; Schema: medcea; Owner: postgres
--

ALTER TABLE ONLY medcea.recipe_line_cycle_run
    ADD CONSTRAINT recipe_line_cycle_run_uk UNIQUE (recipe_run_id, recipe_id, recipe_item_seq_id, recipe_item_seq_cycle_num);


--
-- Name: recipe_line recipe_line_pkey; Type: CONSTRAINT; Schema: medcea; Owner: postgres
--

ALTER TABLE ONLY medcea.recipe_line
    ADD CONSTRAINT recipe_line_pkey PRIMARY KEY (recipe_id, recipe_item_seq_id);


--
-- Name: recipe recipe_name_uk; Type: CONSTRAINT; Schema: medcea; Owner: postgres
--

ALTER TABLE ONLY medcea.recipe
    ADD CONSTRAINT recipe_name_uk UNIQUE (recipe_name);


--
-- Name: recipe recipe_pkey; Type: CONSTRAINT; Schema: medcea; Owner: postgres
--

ALTER TABLE ONLY medcea.recipe
    ADD CONSTRAINT recipe_pkey PRIMARY KEY (recipe_id);


--
-- Name: recipe_run recipe_run_pkey; Type: CONSTRAINT; Schema: medcea; Owner: postgres
--

ALTER TABLE ONLY medcea.recipe_run
    ADD CONSTRAINT recipe_run_pkey PRIMARY KEY (recipe_run_id);


--
-- Name: recipe_unit_permission recipe_unit_permission_pkey; Type: CONSTRAINT; Schema: medcea; Owner: postgres
--

ALTER TABLE ONLY medcea.recipe_unit_permission
    ADD CONSTRAINT recipe_unit_permission_pkey PRIMARY KEY (recipe_id, unit_id);


--
-- Name: device serial_number_uk; Type: CONSTRAINT; Schema: medcea; Owner: postgres
--

ALTER TABLE ONLY medcea.device
    ADD CONSTRAINT serial_number_uk UNIQUE NULLS NOT DISTINCT (serial_number);


--
-- Name: cea_unit unit_code_uk; Type: CONSTRAINT; Schema: medcea; Owner: postgres
--

ALTER TABLE ONLY medcea.cea_unit
    ADD CONSTRAINT unit_code_uk UNIQUE (unit_code);


--
-- Name: cea_unit unit_pkey; Type: CONSTRAINT; Schema: medcea; Owner: postgres
--

ALTER TABLE ONLY medcea.cea_unit
    ADD CONSTRAINT unit_pkey PRIMARY KEY (unit_id);


--
-- Name: idx_recipe_line_recipe_id_item_seq_id; Type: INDEX; Schema: medcea; Owner: postgres
--

CREATE INDEX idx_recipe_line_recipe_id_item_seq_id ON medcea.recipe_line USING btree (recipe_id, recipe_item_seq_id);


--
-- Name: idx_recipe_recipe_id; Type: INDEX; Schema: medcea; Owner: postgres
--

CREATE INDEX idx_recipe_recipe_id ON medcea.recipe USING btree (recipe_id);


--
-- Name: idx_recipe_run_recipe_id; Type: INDEX; Schema: medcea; Owner: postgres
--

CREATE INDEX idx_recipe_run_recipe_id ON medcea.recipe_run USING btree (recipe_id);


--
-- Name: idx_recipe_run_run_id; Type: INDEX; Schema: medcea; Owner: postgres
--

CREATE INDEX idx_recipe_run_run_id ON medcea.recipe_run USING btree (recipe_run_id);


--
-- Name: idx_recipe_run_status_recipe_id; Type: INDEX; Schema: medcea; Owner: postgres
--

CREATE INDEX idx_recipe_run_status_recipe_id ON medcea.recipe_run USING btree (recipe_run_status, recipe_id);


--
-- Name: idx_rlcr_run_id_recipe_id_item_seq_id_cycle_num; Type: INDEX; Schema: medcea; Owner: postgres
--

CREATE INDEX idx_rlcr_run_id_recipe_id_item_seq_id_cycle_num ON medcea.recipe_line_cycle_run USING btree (recipe_run_id, recipe_id, recipe_item_seq_id, recipe_item_seq_cycle_num);


--
-- Name: recipe_run cea_unit-recipe_run; Type: FK CONSTRAINT; Schema: medcea; Owner: postgres
--

ALTER TABLE ONLY medcea.recipe_run
    ADD CONSTRAINT "cea_unit-recipe_run" FOREIGN KEY (unit_id) REFERENCES medcea.cea_unit(unit_id);


--
-- Name: cea_unit cea_unit_location_id_fkey; Type: FK CONSTRAINT; Schema: medcea; Owner: postgres
--

ALTER TABLE ONLY medcea.cea_unit
    ADD CONSTRAINT cea_unit_location_id_fkey FOREIGN KEY (location_id) REFERENCES medcea.cea_location(location_id);


--
-- Name: device cea_zone-device; Type: FK CONSTRAINT; Schema: medcea; Owner: postgres
--

ALTER TABLE ONLY medcea.device
    ADD CONSTRAINT "cea_zone-device" FOREIGN KEY (zone_id) REFERENCES medcea.cea_zone(zone_id);


--
-- Name: component component-device; Type: FK CONSTRAINT; Schema: medcea; Owner: postgres
--

ALTER TABLE ONLY medcea.component
    ADD CONSTRAINT "component-device" FOREIGN KEY (device_id) REFERENCES medcea.device(device_id);


--
-- Name: recipe_run recipe-recipe_run; Type: FK CONSTRAINT; Schema: medcea; Owner: postgres
--

ALTER TABLE ONLY medcea.recipe_run
    ADD CONSTRAINT "recipe-recipe_run" FOREIGN KEY (recipe_id) REFERENCES medcea.recipe(recipe_id);


--
-- Name: recipe_line recipe_id_fk; Type: FK CONSTRAINT; Schema: medcea; Owner: postgres
--

ALTER TABLE ONLY medcea.recipe_line
    ADD CONSTRAINT recipe_id_fk FOREIGN KEY (recipe_id) REFERENCES medcea.recipe(recipe_id);


--
-- Name: recipe_line_cycle_run recipe_line-recipe_line_cycle_run; Type: FK CONSTRAINT; Schema: medcea; Owner: postgres
--

ALTER TABLE ONLY medcea.recipe_line_cycle_run
    ADD CONSTRAINT "recipe_line-recipe_line_cycle_run" FOREIGN KEY (recipe_id, recipe_item_seq_id) REFERENCES medcea.recipe_line(recipe_id, recipe_item_seq_id);


--
-- Name: recipe_line_cycle_run recipe_run-recipe_line_cycle_run; Type: FK CONSTRAINT; Schema: medcea; Owner: postgres
--

ALTER TABLE ONLY medcea.recipe_line_cycle_run
    ADD CONSTRAINT "recipe_run-recipe_line_cycle_run" FOREIGN KEY (recipe_run_id) REFERENCES medcea.recipe_run(recipe_run_id);


--
-- Name: recipe_unit_permission recipe_unit_permission_recipe_id_fkey; Type: FK CONSTRAINT; Schema: medcea; Owner: postgres
--

ALTER TABLE ONLY medcea.recipe_unit_permission
    ADD CONSTRAINT recipe_unit_permission_recipe_id_fkey FOREIGN KEY (recipe_id) REFERENCES medcea.recipe(recipe_id) ON DELETE CASCADE;


--
-- Name: recipe_unit_permission recipe_unit_permission_unit_id_fkey; Type: FK CONSTRAINT; Schema: medcea; Owner: postgres
--

ALTER TABLE ONLY medcea.recipe_unit_permission
    ADD CONSTRAINT recipe_unit_permission_unit_id_fkey FOREIGN KEY (unit_id) REFERENCES medcea.cea_unit(unit_id) ON DELETE CASCADE;


--
-- Name: cea_zone zone_unit_fk; Type: FK CONSTRAINT; Schema: medcea; Owner: postgres
--

ALTER TABLE ONLY medcea.cea_zone
    ADD CONSTRAINT zone_unit_fk FOREIGN KEY (unit_id) REFERENCES medcea.cea_unit(unit_id);


--
-- PostgreSQL database dump complete
--

\unrestrict 7rmBgPZzF3G0lEacS7r0sASHMTy3HOL0PDECnKChymSdto396bdhbAPAqqsCIlo

