
# Database connection details
def connect_to_db(db_config):
    import psycopg2
    """Establishes a connection to the database."""
    try:
        conn = psycopg2.connect(**db_config)
        return conn
    except psycopg2.Error as e:
        print(f"Error connecting to database: {e}")
        return None
