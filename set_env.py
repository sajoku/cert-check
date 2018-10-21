#!/bin/env python3

import bcrypt
import configparser
import os
import uuid


if __name__ == '__main__':
    # get env vars from the config file
    env_file = 'environments/local.ini'
    confpar = configparser.ConfigParser()
    confpar.read(env_file)
    db_name = confpar['default'].get('db_name')
    username = confpar['default'].get('username')
    password = confpar['default'].get('password')
    mm_secret_key = uuid.uuid4().hex
    # set env vars
    os.environ['MM_SECRET_KEY'] = mm_secret_key
    os.environ['MONGO_DB_NAME'] = db_name
    os.environ['MONGO_USERNAME'] = username
    os.environ['MONGO_PASWORD'] = str(bcrypt.hashpw(
        bytes(password, 'utf-8'),
        bcrypt.gensalt(),
    ), 'utf-8')
