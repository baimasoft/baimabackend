import configparser
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

config = configparser.ConfigParser()

config.read("alembic.ini")

SQLALCHEMY_DATABASE_URL = config.get("alembic", "sqlalchemy.url")

engine = create_engine(SQLALCHEMY_DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()