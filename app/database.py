import configparser
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from common import in_docker

config = configparser.ConfigParser()

config.read("config.ini")

if in_docker():
    database_url = config["database"]["DOCKER_URL"]
else:
    database_url = config["database"]["LOCAL_URL"]
    
engine = create_engine(database_url)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()