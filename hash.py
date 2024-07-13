import bcrypt
from session import Session
from db import cursor, conn, commit
from models import User
from utils import Response

session = Session()
@commit
def login(username: str, password: str):
    user: User | None = session.check_session()
    if user:
        return Response('You already logged in', 404)
    get_user_by_username = '''
    SELECT * FROM users WHERE username = %s;
    '''
    cursor.execute(get_user_by_username, (username,))
    user_data = cursor.fetchone()
    if not user_data:
        return Response('User not found', 404)
    
    user = User(username=user_data[1], password=user_data[2], role=user_data[3],
                status=user_data[4], login_try_count=user_data[5])
    
    if not bcrypt.checkpw(password.encode('utf-8'), user_data[2].encode('utf-8')):
        update_user_query = '''
        UPDATE users SET login_try_count = login_try_count + 1 WHERE username = %s;
        '''
        cursor.execute(update_user_query, (username,))
        return Response('Wrong Password', 404)
    
    session.add_session(user)
    return Response('User successfully logged in', 200)

response = login('admin', '1234')

if response.status_code == 200:
    print('True')
else:
    print('False')
@commit
def create_user(username: str, password: str, role: str, status: str):
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    
    insert_user_query = '''
    INSERT INTO users (username, password, role, status, login_try_count)
    VALUES (%s, %s, %s, %s, 0);
    '''
    cursor.execute(insert_user_query, (username, hashed_password.decode('utf-8'), role, status))
    return Response('User created successfully', 201)

session = Session()

@commit
def login(username: str, password: str):
    user: User | None = session.check_session()
    if user:
        return Response('You already logged in', 404)
    
    get_user_by_username = '''
    SELECT * FROM users WHERE username = %s;
    '''
    cursor.execute(get_user_by_username, (username,))
    user_data = cursor.fetchone()
    if not user_data:
        return Response('User not found', 404)
    
    user = User(username=user_data[1], password=user_data[2], role=user_data[3],
                status=user_data[4], login_try_count=user_data[5])
    
    if not bcrypt.checkpw(password.encode('utf-8'), user_data[2].encode('utf-8')):
        update_user_query = '''
        UPDATE users SET login_try_count = login_try_count + 1 WHERE username = %s;
        '''
        cursor.execute(update_user_query, (username,))
        return Response('Wrong Password', 404)
    
    session.add_session(user)
    return Response('User successfully logged in', 200)

@commit
def register(username: str, password: str, role: str, status: str):
    get_user_by_username = '''
    SELECT * FROM users WHERE username = %s;
    '''
    cursor.execute(get_user_by_username, (username,))
    user_data = cursor.fetchone()
    if user_data:
        return Response('Username already exists', 400)
    
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    
    insert_user_query = '''
    INSERT INTO users (username, password, role, status, login_try_count)
    VALUES (%s, %s, %s, %s, 0);
    '''
    cursor.execute(insert_user_query, (username, hashed_password.decode('utf-8'), role, status))
    return Response('User created successfully', 201)

login_response = login('admin', '1234')
if login_response.status_code == 200:
    print('True')
else:
    print('False')
register_response = register('new_user', 'new_password', 'user', 'active')
if register_response.status_code == 201:
    print('True')
else:
    print('False')
