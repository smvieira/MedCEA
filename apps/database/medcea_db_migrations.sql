-- medcea_db_migrations.sql
-- Post-DDL migrations applied by deploy.sh after pg_restore.
-- All statements are idempotent (IF NOT EXISTS / ON CONFLICT DO NOTHING).
-- Add new migrations at the bottom; never remove old ones.

-- ── Migration 001: Control Algorithm registry ────────────────────────────────

CREATE SEQUENCE IF NOT EXISTS medcea.control_algorithm_algorithm_id_seq
    AS integer START WITH 1 INCREMENT BY 1 NO MINVALUE NO MAXVALUE CACHE 1;

CREATE TABLE IF NOT EXISTS medcea.control_algorithm (
    algorithm_id    INTEGER DEFAULT nextval('medcea.control_algorithm_algorithm_id_seq') NOT NULL,
    algorithm_code  VARCHAR(20) NOT NULL,
    algorithm_name  VARCHAR(100) NOT NULL,
    description     TEXT,
    default_params  JSONB NOT NULL DEFAULT '{}',
    is_active       VARCHAR(1) NOT NULL DEFAULT 'Y' CHECK (is_active IN ('Y','N'))
);

DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'control_algorithm_pkey') THEN
        ALTER TABLE ONLY medcea.control_algorithm ADD CONSTRAINT control_algorithm_pkey PRIMARY KEY (algorithm_id);
    END IF;
END $$;

DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'control_algorithm_code_uk') THEN
        ALTER TABLE ONLY medcea.control_algorithm ADD CONSTRAINT control_algorithm_code_uk UNIQUE (algorithm_code);
    END IF;
END $$;

DO $$ BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE c.relname = 'control_algorithm_algorithm_id_seq' AND n.nspname = 'medcea'
          AND c.relkind = 'S'
    ) THEN
        NULL; -- sequence already handled by CREATE SEQUENCE IF NOT EXISTS above
    END IF;
    ALTER SEQUENCE IF EXISTS medcea.control_algorithm_algorithm_id_seq OWNED BY medcea.control_algorithm.algorithm_id;
END $$;

COMMENT ON TABLE  medcea.control_algorithm IS 'Registry of available feedback control algorithms. Each row defines an algorithm that can be selected per recipe-unit combination or per schedule run.';
COMMENT ON COLUMN medcea.control_algorithm.algorithm_id   IS 'Unique identifier for the control algorithm.';
COMMENT ON COLUMN medcea.control_algorithm.algorithm_code IS 'Short machine-readable code used in Python factory (e.g. IF_THEN_ELSE, PID, FLC, MPC, Q_LEARNING).';
COMMENT ON COLUMN medcea.control_algorithm.algorithm_name IS 'Human-readable display name shown in the UI.';
COMMENT ON COLUMN medcea.control_algorithm.description    IS 'Description of the algorithm and its intended use context.';
COMMENT ON COLUMN medcea.control_algorithm.default_params IS 'Default tuning parameters as JSON (e.g. {"kp":1.0,"ki":0.1}). Editable by admin from the UI. Used as the base when no override is provided.';
COMMENT ON COLUMN medcea.control_algorithm.is_active      IS 'Y if the algorithm is available for selection; N to hide it from the UI without deleting it.';

-- Seed the five supported algorithms (idempotent)
INSERT INTO medcea.control_algorithm (algorithm_code, algorithm_name, description, default_params) VALUES
  ('IF_THEN_ELSE', 'If-Then-Else',
   'Simple on/off hysteresis: actuator fully on below lower limit, off within range, fully on above upper limit. No tuning parameters required.',
   '{}'),
  ('PID', 'PID Controller',
   'Proportional-integral-derivative controller. Smooth continuous response. kp=proportional gain, ki=integral gain, kd=derivative gain.',
   '{"kp":1.0,"ki":0.1,"kd":0.05}'),
  ('FLC', 'Fuzzy Logic Control',
   'Fuzzy rule-based control. IEEE-validated for Pleurotus ostreatus cultivation (+37% yield vs if_then_else). deadband_fraction as fraction of setpoint span.',
   '{"deadband_fraction":0.1}'),
  ('MPC', 'Model Predictive Control',
   'Receding-horizon optimal control. Minimises actuator switching over a future horizon. horizon=number of 10s steps to look ahead, switching_cost=penalty weight.',
   '{"horizon":6,"switching_cost":0.1}'),
  ('Q_LEARNING', 'Q-Learning',
   'Reinforcement learning. Learns the chamber thermal dynamics over time. Q-table persisted per unit between recipe runs to avoid cold-start.',
   '{"alpha":0.1,"gamma":0.95,"epsilon":0.2,"epsilon_decay":0.995}')
ON CONFLICT (algorithm_code) DO NOTHING;

-- ── Migration 002: Algorithm selection on recipe_unit_permission ─────────────

ALTER TABLE medcea.recipe_unit_permission
    ADD COLUMN IF NOT EXISTS algorithm_id     INTEGER,
    ADD COLUMN IF NOT EXISTS algorithm_params JSONB DEFAULT NULL;

DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'rup_algorithm_id_fkey') THEN
        ALTER TABLE ONLY medcea.recipe_unit_permission
            ADD CONSTRAINT rup_algorithm_id_fkey
            FOREIGN KEY (algorithm_id) REFERENCES medcea.control_algorithm(algorithm_id);
    END IF;
END $$;

COMMENT ON COLUMN medcea.recipe_unit_permission.algorithm_id     IS 'Default control algorithm for this recipe on this unit. Set by the operator in the Recipe x Unit permission matrix. NULL falls back to IF_THEN_ELSE at runtime.';
COMMENT ON COLUMN medcea.recipe_unit_permission.algorithm_params IS 'Optional parameter overrides for the selected algorithm, applied on top of control_algorithm.default_params for this recipe-unit combination.';

-- ── Migration 003: Algorithm state persistence (Q-table etc.) ────────────────

CREATE TABLE IF NOT EXISTS medcea.algorithm_state (
    unit_id     INTEGER NOT NULL,
    algorithm   VARCHAR(20) NOT NULL,
    channel     VARCHAR(50) NOT NULL,
    state       JSONB NOT NULL DEFAULT '{}',
    updated_at  TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    CONSTRAINT algorithm_state_pkey PRIMARY KEY (unit_id, algorithm, channel)
);

DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'algorithm_state_unit_fkey') THEN
        ALTER TABLE ONLY medcea.algorithm_state
            ADD CONSTRAINT algorithm_state_unit_fkey
            FOREIGN KEY (unit_id) REFERENCES medcea.cea_unit(unit_id);
    END IF;
END $$;

COMMENT ON TABLE  medcea.algorithm_state IS 'Persists in-memory algorithm state (e.g. Q-learning Q-table) between recipe cycle runs for a given unit and sensor channel. Allows stateful algorithms to accumulate knowledge about a specific chamber across runs rather than restarting from scratch each cycle.';
COMMENT ON COLUMN medcea.algorithm_state.unit_id    IS 'The production unit whose learned state is stored. Each unit builds its own policy independently.';
COMMENT ON COLUMN medcea.algorithm_state.algorithm  IS 'Algorithm code matching medcea.control_algorithm.algorithm_code (e.g. Q_LEARNING).';
COMMENT ON COLUMN medcea.algorithm_state.channel    IS 'Sensor channel the state applies to (e.g. air_temperature, co2, air_humidity, substrate_temperature). Each channel has an independent state.';
COMMENT ON COLUMN medcea.algorithm_state.state      IS 'Serialised algorithm state as JSON. For Q_LEARNING: {"q_table": {...}, "epsilon": 0.15}. Loaded at cycle start, saved at cycle end.';
COMMENT ON COLUMN medcea.algorithm_state.updated_at IS 'Timestamp of the last state save. Used to detect stale state after hardware changes.';
