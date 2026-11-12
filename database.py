
import os
from pathlib import Path

import mysql.connector

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass


BASE_DIR = Path(__file__).resolve().parent


def get_connection():
    try:
        tidb_host = os.getenv("TIDB_HOST")

        if tidb_host:
            connection = mysql.connector.connect(
                host=tidb_host,
                port=int(os.getenv("TIDB_PORT", "4000")),
                user=os.getenv("TIDB_USER"),
                password=os.getenv("TIDB_PASSWORD"),
                database=os.getenv("DB_NAME", "blood_network"),
                ssl_ca=os.getenv(
                    "TIDB_SSL_CA",
                    str(BASE_DIR / "isrgrootx1.pem")
                ),
                ssl_verify_cert=True,
                ssl_verify_identity=True,
                connection_timeout=15
            )

            print("TiDB Cloud Connected Successfully!")
            return connection

        local_password = os.getenv("DB_PASSWORD")

        if not local_password:
            print("Database connection error: DB_PASSWORD is not configured.")
            return None

        connection = mysql.connector.connect(
            host=os.getenv("DB_HOST", "localhost"),
            port=int(os.getenv("DB_PORT", "3306")),
            user=os.getenv("DB_USER", "root"),
            password=local_password,
            database=os.getenv("DB_NAME", "blood_network"),
            connection_timeout=15
        )

        print("Local MySQL Connected Successfully!")
        return connection

    except mysql.connector.Error as error:
        print("Database connection error:", error)
        return None
