import sqlalchemy
from sqlalchemy import create_engine

engine = create_engine("sqlite:///app.db")

def query(sql):
    # Intentional SQLi sink — used by users.list_users below.
    with engine.connect() as conn:
        return conn.execute(sqlalchemy.text(sql)).fetchall()
