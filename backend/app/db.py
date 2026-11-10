from pymongo import MongoClient, ASCENDING, DESCENDING
from neo4j import GraphDatabase
from .config import settings

mongo_client = MongoClient(settings.mongo_uri, serverSelectionTimeoutMS=5000)
db = mongo_client[settings.mongo_database]
neo_driver = None

def init_db():
    global neo_driver
    mongo_client.admin.command("ping")
    db.users.create_index("email", unique=True)
    db.indicators.create_index([("type", ASCENDING), ("value", ASCENDING)], unique=True)
    db.indicators.create_index([("created_at", DESCENDING)])
    db.alerts.create_index([("created_at", DESCENDING)])
    db.alerts.create_index("status")
    db.audit_logs.create_index([("created_at", DESCENDING)])
    if neo_driver is None:
        neo_driver = GraphDatabase.driver(
            settings.neo4j_uri,
            auth=(settings.neo4j_username, settings.neo4j_password),
            connection_timeout=5,
        )
    neo_driver.verify_connectivity()
    with neo_driver.session() as session:
        session.run("CREATE CONSTRAINT entity_key IF NOT EXISTS FOR (n:Entity) REQUIRE n.key IS UNIQUE")

def close_db():
    global neo_driver
    mongo_client.close()
    if neo_driver:
        neo_driver.close()
        neo_driver = None
