import sqlite3
import glob
def update_field(cursor, table, field):
    update_query = f"""
    UPDATE {table}
    SET {field} = REPLACE({field}, 'Other', 'No_response')
    WHERE {field} LIKE '%Other%'
    """
    cursor.execute(update_query)

db_dir = 'database'

# paths = glob.glob(r'cache/checkpoint_v80_v1/*.db')
paths =  [r"cache/checkpoint_T120_v1/cache.db"]
# print(paths)

for path in paths:

    conn = sqlite3.connect(path)

    cur = conn.cursor()

    # 假设您要更新的表名为 'example_table'，需要更新的字段为 'column1', 'column2', ...
    fields_to_update = ['result']
    for field in fields_to_update:
        update_field(cur, 'query_results', field)

    # 提交事务
    conn.commit()

    # 关闭Cursor
    cur.close()

    # 关闭连接
    conn.close()

import DBhelper


db = DBhelper.DBhelper(r'cache/cisco_2951_v1/cache.db')

query = "('main_mode_1', 'main_mode_2', 'main_mode_3', 'quick_mode_2', 'main_mode_1')"

db.delete_query(query)