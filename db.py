import psycopg2
from models import UserRole, UserStatus

db_params = {
    'database': 'n48',
    'user': 'postgres',
    'password': 'qazwsx',
    'host': 'localhost',
    'port': 5432
}

conn = psycopg2.connect(**db_params)
cursor = conn.cursor()

create_user_query = """create table if not exists userse(
    id serial PRIMARY KEY,
    username varchar(100) unique not null,
    password varchar(255) not null,
    "role" varchar(100) not null,
    status varchar(100) not null ,
    login_try_count int not null default 0
);
"""

create_todo_query = """create table if not exists todo(
    id serial primary key,
    name varchar(100) not null,
    description varchar(100),
    todo_type varchar(100) not null,
    user_id int not null references users(id)
);
"""

def todo_update(todo_id, name, description):
    try:
        with psycopg2.connect(db_params) as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE todos SET name = ?, description = ? WHERE id = ?", (name, description, todo_id))
            conn.commit()
        return Response(200, 'Todo updated successfully')
    except Exception as e:
        return Response(500, f'Error: {str(e)}')

def create_table():
    cursor.execute(create_user_query)
    cursor.execute(create_todo_query)


def migrate():
    insert_admin_user_query = """
    insert into userse(username, password, role, status, login_try_count)
    values (%s,%s,%s,%s,%s);
    """
    user_data = ('admin', '123', UserRole.ADMIN.value, UserStatus.ACTIVE.value, 0)
    cursor.execute(insert_admin_user_query, user_data)
    conn.commit()


def init():
    create_table()
    migrate()


def commit(func):
    def wrapper(*args, **kwargs):
        result = func(*args, **kwargs)
        conn.commit()
        return result

    return wrapper


if __name__ == '__main__':
    init()
