from services.user_service import add_user

def create_account():
    """Create a new user account."""
    add_user()
    return "created_account, please check database"