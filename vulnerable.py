import os
import subprocess

# SQL Injection 취약점
def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return execute_query(query)

# Command Injection 취약점  
def backup_file(filename):
    os.system(f"cp {filename} /backup/")

# Hard-coded 비밀번호
API_KEY = "sk-1234567890abcdef"
DATABASE_PASSWORD = "admin123"

def execute_query(query):
    pass