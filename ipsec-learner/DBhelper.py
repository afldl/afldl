import sqlite3
import hashlib
import utils

def str2list(lstr):
    lstr = lstr.strip('[]')
    lst = [out.strip("''") for out in lstr.split(', ')]
    return lst

class DBhelper:
    def __init__(self, db_file):
        self.db_file = db_file
        self.conn = None
        self.cursor = None
        self.connect()
        self.create_table()

    def connect(self):
        self.conn = sqlite3.connect(self.db_file)
        self.cursor = self.conn.cursor()

    def disconnect(self):
        if self.conn:
            self.conn.close()

    def create_table(self):
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS query_results (
                query_hash TEXT PRIMARY KEY,
                query TEXT,
                result TEXT
            )
        ''')
        self.conn.commit()

    def hash_query(self, query):
        return hashlib.sha256(query.encode()).hexdigest()

    def execute_query(self, query):
        query_hash = self.hash_query(query)
        self.cursor.execute('SELECT query, result FROM query_results WHERE query_hash = ?', (query_hash, ))
        existing_result = self.cursor.fetchone()
        if existing_result:
            return existing_result[1]

    def insert_query(self, query, result):
        query_hash = self.hash_query(query)
        existing_result = self.execute_query(query)
        if existing_result:
            return
        self.cursor.execute('INSERT INTO query_results (query_hash, query, result) VALUES (?, ?, ?)', (query_hash, query, result))
        self.conn.commit()
        # print("insert to database")

    def update_query(self, query, new_result):
        query_hash = self.hash_query(query)
        self.cursor.execute('UPDATE query_results SET result = ? WHERE query_hash = ?', (new_result, query_hash))
        self.conn.commit()

    def delete_query(self, query):
        query_hash = self.hash_query(query)
        self.cursor.execute('DELETE FROM query_results WHERE query_hash = ?', (query_hash,))
        self.conn.commit()

    def delete_hash(self, hash):
        self.cursor.execute('DELETE FROM query_results WHERE query_hash = ?', (hash,))
        self.conn.commit()

    def clear_database(self):
        self.cursor.execute('DELETE FROM query_results')
        self.conn.commit()
        
    def fetch_all_entries(self):
        self.cursor.execute('SELECT * FROM query_results')
        entries = self.cursor.fetchall()
        return entries
    
    # 清理和querys results 不对应的所有记录
    def clean_db(self,querys,resposes):
        LEN_QUERYS = len(querys)
        entries = self.fetch_all_entries()
        for item in entries:
            hash,db_querys,db_resposes = item[0],utils.tuple_str2list(item[1]),utils.str2list(item[2])
            if len(db_querys) >= LEN_QUERYS and db_querys[:LEN_QUERYS] == querys and db_resposes[:LEN_QUERYS] != resposes:
                print(f"clean item:{db_querys}:{db_resposes}")
                self.delete_hash(hash)


def get_items_counts(db_path):
    db = DBhelper(db_path)
    # 查询表中的条目数
    db.cursor.execute("SELECT COUNT(*) FROM query_results")
    count = db.cursor.fetchone()[0]

    return count


if __name__ == "__main__":


    db = DBhelper(r'learning/database/IKEv2_learning_strongswan.db')
    # db.clean_db(['INFO_DelIKE'],['No_response'])

    # query = "('SAINIT_SA-KE-NONCE', 'AUTH_IDi-AUTH-SA-TSi-TSr', 'SAINIT_SA-KE-NONCE', 'CHILDSA_RekeyIKE-NONCE', 'SAINIT_SA-KE-NONCE', 'SAINIT_SA-KE-NONCE', 'SAINIT_SA-KE-NONCE')"
    # print(db.delete_query(query))
    # db.create_table()
    query1 = "('INFO_DelIKE', 'SAINIT_SA-KE-NONCE')"
    result1 = "['No_response', 'SAINIT_SA-KE-NONCE-4022-4014']"
    query2 = "('INFO_DelIKE', 'AUTH_IDi-AUTH-SA-TSi-TSr')"
    result2 = "['0', 'SAINIT_SA-KE-NONCE-4022-4014']"
    db.insert_query(query1, result1)
    db.insert_query(query2, result2)
    # with open('temp.txt', 'r') as f:
    #     lines = f.readlines()
    # for line in lines:
    #     query = line.split(' | ')[0]
    #     result = line.split(' | ')[1].strip('\n')
    #     db.insert_query(query, result)
    # db.disconnect()
    pass