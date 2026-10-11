-- medcea_db export
-- Generated: 2026-03-13 13:21:06.770704 UTC

-- Domain: medcea.is_active
CREATE DOMAIN medcea.is_active AS character varying
  CHECK (VALUE::text ~ 'Y'::text OR VALUE::text ~ 'N'::text);

-- Domain: medcea.light_types
CREATE DOMAIN medcea.light_types AS character varying
  CHECK (VALUE::text ~ 'UV'::text OR VALUE::text ~ 'BLUE'::text OR VALUE::text ~ 'RED'::text OR VALUE::text ~ 'DARK'::text);

-- Domain: medcea.msg_type
CREATE DOMAIN medcea.msg_type AS character varying(2)
  CHECK (VALUE::text ~ 'AP'::text OR VALUE::text ~ 'CT'::text OR VALUE::text ~ 'SP'::text);

-- Domain: medcea.run_status
CREATE DOMAIN medcea.run_status AS character varying
  CHECK (VALUE::text ~ 'F'::text OR VALUE::text ~ 'R'::text OR VALUE::text ~ 'S'::text OR VALUE::text ~ 'C'::text);

-- Domain: medcea.unit_type
CREATE DOMAIN medcea.unit_type AS character varying(10)
  CHECK (VALUE::text ~ 'Greens'::text OR VALUE::text ~ 'Mushrooms'::text OR VALUE::text ~ 'Other'::text);

-- Sequence: medcea.cea_location_location_id_seq
CREATE SEQUENCE IF NOT EXISTS medcea.cea_location_location_id_seq
  START WITH 1
  INCREMENT BY 1
  MINVALUE 1
  MAXVALUE 2147483647
  NO CYCLE;

-- Sequence: medcea.cea_unit_unit_id_seq
CREATE SEQUENCE IF NOT EXISTS medcea.cea_unit_unit_id_seq
  START WITH 1
  INCREMENT BY 1
  MINVALUE 1
  MAXVALUE 2147483647
  NO CYCLE;

-- Sequence: medcea.cea_zone_zone_id_seq
CREATE SEQUENCE IF NOT EXISTS medcea.cea_zone_zone_id_seq
  START WITH 1
  INCREMENT BY 1
  MINVALUE 1
  MAXVALUE 9223372036854775807
  NO CYCLE;

-- Sequence: medcea.component_component_id_seq
CREATE SEQUENCE IF NOT EXISTS medcea.component_component_id_seq
  START WITH 1
  INCREMENT BY 1
  MINVALUE 1
  MAXVALUE 2147483647
  NO CYCLE;

-- Sequence: medcea.device_device_id_seq
CREATE SEQUENCE IF NOT EXISTS medcea.device_device_id_seq
  START WITH 1
  INCREMENT BY 1
  MINVALUE 1
  MAXVALUE 2147483647
  NO CYCLE;

-- Sequence: medcea.recipe_line_cycle_run_recipe_line_cycle_run_id_seq
CREATE SEQUENCE IF NOT EXISTS medcea.recipe_line_cycle_run_recipe_line_cycle_run_id_seq
  START WITH 1
  INCREMENT BY 1
  MINVALUE 1
  MAXVALUE 2147483647
  NO CYCLE;

-- Sequence: medcea.recipe_recipe_id_seq
CREATE SEQUENCE IF NOT EXISTS medcea.recipe_recipe_id_seq
  START WITH 1
  INCREMENT BY 1
  MINVALUE 1
  MAXVALUE 9223372036854775807
  NO CYCLE;

-- Sequence: medcea.recipe_run_recipe_run_id_seq
CREATE SEQUENCE IF NOT EXISTS medcea.recipe_run_recipe_run_id_seq
  START WITH 1
  INCREMENT BY 1
  MINVALUE 1
  MAXVALUE 2147483647
  NO CYCLE;

-- Table: medcea.backup_remote_to_insert_measurement
CREATE TABLE IF NOT EXISTS medcea.backup_remote_to_insert_measurement (
  measure_timestamp timestamp with time zone,
  device_id character varying,
  device_dns character varying,
  msg_type medcea.msg_type,
  msg json,
  timestamp timestamp with time zone
);

-- Table: medcea.cea_location
CREATE TABLE IF NOT EXISTS medcea.cea_location (
  location_id integer DEFAULT nextval('medcea.cea_location_location_id_seq'::regclass) NOT NULL,
  name character varying(255) NOT NULL,
  address character varying(255),
  latitude numeric,
  longitude numeric,
  contact_person character varying(255),
  contact_info character varying(255),
  description text,
  is_active medcea.is_active,
  PRIMARY KEY (location_id)
);

-- Table: medcea.cea_unit
CREATE TABLE IF NOT EXISTS medcea.cea_unit (
  unit_id integer DEFAULT nextval('medcea.cea_unit_unit_id_seq'::regclass) NOT NULL,
  unit_type medcea.unit_type NOT NULL,
  description character varying,
  location_id integer NOT NULL,
  area double precision,
  height double precision,
  timestamp timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
  is_active medcea.is_active NOT NULL,
  unit_code character varying(10) NOT NULL,
  PRIMARY KEY (unit_id),
  CONSTRAINT unit_code_uk UNIQUE (unit_code)
);
ALTER TABLE medcea.cea_unit ADD CONSTRAINT cea_unit_location_id_fkey FOREIGN KEY (location_id) REFERENCES medcea.cea_location(location_id);

-- Table: medcea.cea_zone
CREATE TABLE IF NOT EXISTS medcea.cea_zone (
  unit_id integer NOT NULL,
  zone_id integer DEFAULT nextval('medcea.cea_zone_zone_id_seq'::regclass) NOT NULL,
  zone_code character varying NOT NULL,
  zone_description character varying,
  timestamp_cre timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
  is_active medcea.is_active NOT NULL,
  PRIMARY KEY (zone_id)
);
ALTER TABLE medcea.cea_zone ADD CONSTRAINT zone_unit_fk FOREIGN KEY (unit_id) REFERENCES medcea.cea_unit(unit_id);

-- Table: medcea.component
CREATE TABLE IF NOT EXISTS medcea.component (
  component_id integer DEFAULT nextval('medcea.component_component_id_seq'::regclass) NOT NULL,
  device_id integer NOT NULL,
  component_type character varying(8),
  model character varying(255),
  manufacturer character varying(255),
  parameters json,
  is_active medcea.is_active DEFAULT 'Y'::character varying,
  timestamp_cre timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (component_id)
);
ALTER TABLE medcea.component ADD CONSTRAINT component-device FOREIGN KEY (device_id) REFERENCES medcea.device(device_id);

-- Table: medcea.databasechangeloglock
CREATE TABLE IF NOT EXISTS medcea.databasechangeloglock (
  id integer NOT NULL,
  locked boolean NOT NULL,
  lockgranted timestamp without time zone,
  lockedby character varying(255),
  PRIMARY KEY (id)
);

-- Table: medcea.device
CREATE TABLE IF NOT EXISTS medcea.device (
  device_id integer DEFAULT nextval('medcea.device_device_id_seq'::regclass) NOT NULL,
  zone_id integer,
  device_type character varying(255) NOT NULL,
  model character varying(255),
  manufacturer character varying(255),
  serial_number character varying(255) NOT NULL,
  connection_type character varying(255) DEFAULT 'WiFi'::character varying NOT NULL,
  dns_name character varying(255) NOT NULL,
  installation_date date DEFAULT CURRENT_TIMESTAMP,
  is_active medcea.is_active DEFAULT 'Y'::character varying,
  PRIMARY KEY (device_id),
  CONSTRAINT dns_name_uk UNIQUE (dns_name),
  CONSTRAINT serial_number_uk UNIQUE (serial_number)
);
ALTER TABLE medcea.device ADD CONSTRAINT cea_zone-device FOREIGN KEY (zone_id) REFERENCES medcea.cea_zone(zone_id);

-- Table: medcea.measurement
CREATE TABLE IF NOT EXISTS medcea.measurement (
  measure_timestamp timestamp with time zone NOT NULL,
  device_id character varying NOT NULL,
  device_dns character varying NOT NULL,
  msg_type medcea.msg_type NOT NULL,
  msg json NOT NULL,
  timestamp timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL
);

-- Table: medcea.recipe
CREATE TABLE IF NOT EXISTS medcea.recipe (
  recipe_id integer DEFAULT nextval('medcea.recipe_recipe_id_seq'::regclass) NOT NULL,
  recipe_name character varying NOT NULL,
  recipe_description character varying,
  timestamp_cre timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
  timestamp_upd timestamp with time zone,
  is_active character varying DEFAULT 'Y'::character varying NOT NULL,
  PRIMARY KEY (recipe_id),
  CONSTRAINT recipe_name_uk UNIQUE (recipe_name)
);
CREATE INDEX idx_recipe_recipe_id ON medcea.recipe USING btree (recipe_id);

-- Table: medcea.recipe_line
CREATE TABLE IF NOT EXISTS medcea.recipe_line (
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
  notes character varying,
  PRIMARY KEY (recipe_id, recipe_item_seq_id)
);
ALTER TABLE medcea.recipe_line ADD CONSTRAINT recipe_id_fk FOREIGN KEY (recipe_id) REFERENCES medcea.recipe(recipe_id);
CREATE INDEX idx_recipe_line_recipe_id_item_seq_id ON medcea.recipe_line USING btree (recipe_id, recipe_item_seq_id);

-- Table: medcea.recipe_line_cycle_run
CREATE TABLE IF NOT EXISTS medcea.recipe_line_cycle_run (
  recipe_line_cycle_run_id integer DEFAULT nextval('medcea.recipe_line_cycle_run_recipe_line_cycle_run_id_seq'::regclass) NOT NULL,
  recipe_run_id integer NOT NULL,
  recipe_id integer NOT NULL,
  recipe_item_seq_id integer NOT NULL,
  recipe_item_seq_cycle_num integer NOT NULL,
  recipe_line_seq_cycle_run_start timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
  recipe_line_seq_cycle_run_end timestamp with time zone,
  recipe_line_cycle_run_status medcea.run_status NOT NULL,
  run_params json,
  timestamp_cre timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
  timestamp_upd timestamp with time zone,
  PRIMARY KEY (recipe_line_cycle_run_id),
  CONSTRAINT recipe_line_cycle_run_uk UNIQUE (recipe_run_id, recipe_id, recipe_item_seq_id, recipe_item_seq_cycle_num)
);
ALTER TABLE medcea.recipe_line_cycle_run ADD CONSTRAINT recipe_line-recipe_line_cycle_run FOREIGN KEY (recipe_id, recipe_item_seq_id) REFERENCES medcea.recipe_line(recipe_id, recipe_item_seq_id);
ALTER TABLE medcea.recipe_line_cycle_run ADD CONSTRAINT recipe_run-recipe_line_cycle_run FOREIGN KEY (recipe_run_id) REFERENCES medcea.recipe_run(recipe_run_id);
CREATE INDEX idx_rlcr_run_id_recipe_id_item_seq_id_cycle_num ON medcea.recipe_line_cycle_run USING btree (recipe_run_id, recipe_id, recipe_item_seq_id, recipe_item_seq_cycle_num);

-- Table: medcea.recipe_run
CREATE TABLE IF NOT EXISTS medcea.recipe_run (
  recipe_run_id integer DEFAULT nextval('medcea.recipe_run_recipe_run_id_seq'::regclass) NOT NULL,
  recipe_id integer NOT NULL,
  unit_id integer NOT NULL,
  recipe_run_start timestamp with time zone NOT NULL,
  recipe_run_end timestamp with time zone,
  timestamp_cre timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
  timestamp_upd timestamp with time zone,
  recipe_run_status medcea.run_status NOT NULL,
  is_active medcea.is_active NOT NULL,
  PRIMARY KEY (recipe_run_id)
);
ALTER TABLE medcea.recipe_run ADD CONSTRAINT cea_unit-recipe_run FOREIGN KEY (unit_id) REFERENCES medcea.cea_unit(unit_id);
ALTER TABLE medcea.recipe_run ADD CONSTRAINT recipe-recipe_run FOREIGN KEY (recipe_id) REFERENCES medcea.recipe(recipe_id);
CREATE INDEX idx_recipe_run_recipe_id ON medcea.recipe_run USING btree (recipe_id);
CREATE INDEX idx_recipe_run_run_id ON medcea.recipe_run USING btree (recipe_run_id);
CREATE INDEX idx_recipe_run_status_recipe_id ON medcea.recipe_run USING btree (recipe_run_status, recipe_id);

-- Table: medcea.recipe_unit_permission
CREATE TABLE IF NOT EXISTS medcea.recipe_unit_permission (
  recipe_id integer NOT NULL,
  unit_id integer NOT NULL,
  allowed boolean DEFAULT true NOT NULL,
  PRIMARY KEY (recipe_id, unit_id)
);
ALTER TABLE medcea.recipe_unit_permission ADD CONSTRAINT recipe_unit_permission_recipe_id_fkey FOREIGN KEY (recipe_id) REFERENCES medcea.recipe(recipe_id) ON DELETE CASCADE;
ALTER TABLE medcea.recipe_unit_permission ADD CONSTRAINT recipe_unit_permission_unit_id_fkey FOREIGN KEY (unit_id) REFERENCES medcea.cea_unit(unit_id) ON DELETE CASCADE;

-- View: medcea.msg_actual_points
CREATE OR REPLACE VIEW medcea.msg_actual_points AS
 SELECT msg ->> 'unit_code'::text AS unit_code,
    msg ->> 'zone_code'::text AS zone_code,
    msg ->> 'timestamp'::text AS measure_timestamp,
    msg ->> 'msg_type'::text AS msg_type,
    msg ->> 'tag'::text AS tag,
    msg ->> 'device_dns'::text AS device_dns,
    msg ->> 'value'::text AS value,
    msg ->> 'UoM'::text AS uom,
    msg ->> 'device_id'::text AS device_id,
    "timestamp" AS record_timestamp,
    msg
   FROM medcea.measurement
  WHERE msg_type::text = 'AP'::text;;

-- View: medcea.msg_controls
CREATE OR REPLACE VIEW medcea.msg_controls AS
 SELECT measurement.msg ->> 'unit_code'::text AS unit_code,
    measurement.msg ->> 'zone_code'::text AS unit_zone,
    measurement.msg ->> 'timestamp'::text AS measure_timestamp,
    measurement.msg ->> 'msg_type'::text AS msg_type,
    measurement.msg ->> 'device_id'::text AS device_id,
    json_each.key AS tag,
    json_each.value::text AS value,
    measurement.msg
   FROM medcea.measurement,
    LATERAL json_each(measurement.msg) json_each(key, value)
  WHERE measurement.msg_type::text = 'CT'::text AND (json_each.key <> ALL (ARRAY['unit_code'::text, 'unit_zone'::text, 'timestamp'::text, 'msg_type'::text, 'device_dns'::text, 'device_id'::text]));;

-- View: medcea.msg_set_points
CREATE OR REPLACE VIEW medcea.msg_set_points AS
 SELECT msg ->> 'unit_code'::text AS unit_code,
    msg ->> 'unit_zone'::text AS unit_zone,
    msg ->> 'timestamp'::text AS measure_timestamp,
    msg ->> 'msg_type'::text AS msg_type,
    msg ->> 'tag'::text AS tag,
    msg ->> 'device_dns'::text AS device_dns,
    msg ->> 'value'::text AS value,
    msg ->> 'device_id'::text AS device_id,
    "timestamp" AS record_timestamp,
    msg
   FROM medcea.measurement
  WHERE msg_type::text = 'SP'::text;;

-- View: medcea.run_history
CREATE OR REPLACE VIEW medcea.run_history AS
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
   FROM medcea.recipe r
     JOIN medcea.recipe_line rl ON r.recipe_id = rl.recipe_id
     JOIN medcea.recipe_run rr ON rr.recipe_id = r.recipe_id
     LEFT JOIN medcea.recipe_line_cycle_run rlcr ON rr.recipe_run_id = rlcr.recipe_run_id AND rl.recipe_id = rlcr.recipe_id AND rl.recipe_item_seq_id = rlcr.recipe_item_seq_id
  ORDER BY rl.recipe_id, rl.recipe_item_seq_id, rlcr.recipe_item_seq_cycle_num;;

-- View: medcea.run_watch
CREATE OR REPLACE VIEW medcea.run_watch AS
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
   FROM medcea.recipe r
     JOIN medcea.recipe_line rl ON r.recipe_id = rl.recipe_id
     JOIN medcea.recipe_run rr ON rr.recipe_id = r.recipe_id
     LEFT JOIN medcea.recipe_line_cycle_run rlcr ON rr.recipe_run_id = rlcr.recipe_run_id AND rl.recipe_id = rlcr.recipe_id AND rl.recipe_item_seq_id = rlcr.recipe_item_seq_id
  WHERE rr.recipe_run_status::text <> 'C'::text
  ORDER BY rl.recipe_id, rl.recipe_item_seq_id, rlcr.recipe_item_seq_cycle_num;;

-- View: medcea.v_ap_measurements
CREATE OR REPLACE VIEW medcea.v_ap_measurements AS
 SELECT measure_timestamp,
    device_id,
    device_dns,
    msg_type,
    "timestamp" AS db_timestamp,
    msg ->> 'unit_code'::text AS unit_code,
    msg ->> 'zone_code'::text AS zone_code,
    msg ->> 'tag'::text AS tag,
    (msg ->> 'value'::text)::numeric AS value,
    msg ->> 'UoM'::text AS unit_of_measurement,
    (msg ->> 'timestamp'::text)::timestamp without time zone AS message_timestamp,
    msg
   FROM medcea.measurement
  WHERE msg_type::text = 'AP'::text;;

-- View: medcea.v_ct_measurements
CREATE OR REPLACE VIEW medcea.v_ct_measurements AS
 SELECT measure_timestamp,
    device_id,
    device_dns,
    msg_type,
    "timestamp" AS db_timestamp,
    msg ->> 'unit_code'::text AS unit_code,
    msg ->> 'zone_code'::text AS zone_code,
    msg ->> 'tag'::text AS tag,
    msg ->> 'command'::text AS command,
    (msg ->> 'timestamp'::text)::timestamp without time zone AS message_timestamp,
    msg
   FROM medcea.measurement
  WHERE msg_type::text = 'CT'::text;;

-- View: medcea.v_sp_measurements
CREATE OR REPLACE VIEW medcea.v_sp_measurements AS
 SELECT measure_timestamp,
    device_id,
    device_dns,
    msg_type,
    "timestamp" AS db_timestamp,
    msg ->> 'unit_code'::text AS unit_code,
    msg ->> 'zone_code'::text AS zone_code,
    msg ->> 'tag'::text AS tag,
    (msg ->> 'pin'::text)::integer AS pin,
    (msg ->> 'value'::text)::integer AS value,
    (msg ->> 'timestamp'::text)::timestamp without time zone AS message_timestamp,
    msg
   FROM medcea.measurement
  WHERE msg_type::text = 'SP'::text;;
