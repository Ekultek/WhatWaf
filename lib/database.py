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
        'CREATE TABLE IF NOT EXISTS "cached_payloads" ('
        '`id` INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,'
        '`payload` TEXT NOT NULL'
        ')'
    )
    cursor.execute(
        "CREATE TABLE IF NOT EXISTS `cached_urls` ("
        "`id` INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT, "
        "`uri` TEXT NOT NULL, "
        "`working_tampers` TEXT NOT NULL DEFAULT 'N/A', "
        "`identified_protections` TEXT NOT NULL DEFAULT 'N/A',"
        "`identified_webserver`	TEXT NOT NULL DEFAULT 'N/A'"
        ")"
    )
    conn = sqlite3.connect(lib.settings.DATABASE_FILENAME, isolation_level=None, check_same_thread=False)
    return conn.cursor()


def fetch_data(cursor, is_payload=True):
    """
    fetch all payloads out of the database
    """
    try:
        if is_payload:
            cached = cursor.execute("SELECT * FROM cached_payloads")
        else:
            cached = cursor.execute("SELECT * FROM cached_urls")
        retval = cached.fetchall()
    except Exception:
        retval = []
    return retval


def insert_payload(payload, cursor):
    """
    insert a payload into the database
    """
    try:
        is_inserted = False
        current_cache = fetch_data(cursor, is_payload=True)
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


def insert_url(netloc, working_tampers, identified_protections,  cursor, webserver=None, return_found=False):
    """
    insert the URL into the database for future use, will only insert the netlock of the URL for easier
    caching and easier checking, so multiple netlocks of the same URL can hypothetically be used IE:
     - www.foo.bar
     - ftp.foo.bar
     - ssh.foo.bar
    """
    try:
        is_inserted = False
        current_cache = fetch_data(cursor, is_payload=False)
        id_number = len(current_cache) + 1
        if webserver is None:
            webserver = "N/A"
        for item in current_cache:
            _, cached_netloc, _, _, _ = item
            if str(cached_netloc).strip() == str(netloc).strip():
                if return_found:
                    return item
                else:
                    return False
        if not is_inserted:
            if len(identified_protections) > 1:
                if lib.settings.UNKNOWN_FIREWALL_NAME in identified_protections:
                    identified_protections.remove(identified_protections.index(lib.settings.UNKNOWN_FIREWALL_NAME))
                identified_protections = ",".join(identified_protections)
            else:
                try:
                    identified_protections = identified_protections[0]
                except:
                    identified_protections = "N/A"
            if len(working_tampers) > 1:
                working_tampers = ",".join(working_tampers)
            else:
                try:
                    working_tampers = working_tampers[0]
                except:
                    working_tampers = "N/A"
            cursor.execute(
                "INSERT INTO cached_urls ("
                "id,uri,working_tampers,identified_protections,identified_webserver"
                ") VALUES (?,?,?,?,?)",
                (id_number, netloc, identified_protections, working_tampers, webserver)
            )
    except Exception:
        return False
    return True
