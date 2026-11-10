from app.db import db
from app.config import settings
from app.security import hash_password

email = settings.admin_email.lower().strip()

result = db.users.update_one(
    {"email": email},
    {"$set": {
        "password_hash": hash_password(settings.admin_password),
        "active": True
    }}
)

print("Matched:", result.matched_count)
print("Updated:", result.modified_count)
