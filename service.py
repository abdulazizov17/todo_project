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
    select * from users where username = %s;
    '''
    cursor.execute(get_user_by_username, (username,))
    user_data = cursor.fetchone()
    if not user_data:
        return Response('User not found', 404)
    user = User(username=user_data[1], password=user_data[2], role=user_data[3],
                status=user_data[4], login_try_count=user_data[5])
    if password != user_data[2]:
        update_user_query = '''
        update users set login_try_count = login_try_count + 1 where username = %s;
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
