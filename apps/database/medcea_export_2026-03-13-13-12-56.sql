-- medcea_db export
-- Generated: 2026-03-13 13:13:36.236078 UTC

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

-- Data: medcea.cea_zone (2 rows)
INSERT INTO medcea.cea_zone (unit_id, zone_id, zone_code, zone_description, timestamp_cre, is_active) VALUES (1, 1, 'ZONE01', 'There is just this zone', '2026-03-12 13:28:14.149132+00:00', 'Y');
INSERT INTO medcea.cea_zone (unit_id, zone_id, zone_code, zone_description, timestamp_cre, is_active) VALUES (2, 2, 'ZONE01', 'there is only one zone', '2026-03-12 15:53:37.442857+00:00', 'Y');
