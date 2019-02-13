import os
import sqlite3

import lib.settings


def initialize():
    """
    initialize the database and the HOME directory (~/.whatwaf)
    """
    if not os.path.exists(lib.settings.DATABASE_FILENAME):
        # idk why but apparently i never create the directory :|
        if not os.path.exists(lib.settings.HOME):
            try:
                os.makedirs(lib.settings.HOME)
            except:
                pass
        cursor = sqlite3.connect(lib.settings.DATABASE_FILENAME)
        cursor.execute(
            'CREATE TABLE "cached_payloads" ('
            '`id` INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,'
            '`payload` TEXT NOT NULL'
            ')'
        )
    conn = sqlite3.connect(lib.settings.DATABASE_FILENAME, isolation_level=None, check_same_thread=False)
    return conn.cursor()


def fetch_payloads(cursor):
    """
    fetch all payloads out of the database
    """
    try:
        cached_payloads = cursor.execute("SELECT * FROM cached_payloads")
        retval = cached_payloads.fetchall()
    except Exception:
        retval = []
    return retval


def insert_payload(payload, cursor):
    """
    insert a payload into the database
    """
    try:
        is_inserted = False
        current_cache = fetch_payloads(cursor)
        id_number = len(current_cache) + 1
        for item in current_cache:
            _, cache_payload = item
            if cache_payload == payload:
                is_inserted = True
        if not is_inserted:
            cursor.execute(
                "INSERT INTO cached_payloads (id,payload) VALUES (?,?)", (id_number, payload)
            )
    except Exception:
        return False
    return True