import os
from flask import Flask, request, abort, send_from_directory, render_template
from flask_httpauth import HTTPBasicAuth
from werkzeug.security import generate_password_hash, check_password_hash
import mariadb

TABLE_NAME = "test"
FUNCTION_NAME = "uuid_v4"
MAX_URL_LENGTH = 512

app = Flask(__name__, template_folder = 'httpdocs')
auth = HTTPBasicAuth()

http_users = {
    os.environ.get("HTTP_USER") or "test": generate_password_hash(os.environ.get("HTTP_PASS") or "test"),
}
db_host = os.environ.get("DB_HOST") or "localhost"
db_port = os.environ.get("DB_PORT") or "3306"
db_user = os.environ.get("DB_USER") or "test"
db_pass = os.environ.get("DB_PASS") or "test"
db_name = os.environ.get("DB_NAME") or "test"
dbconnector = None
db = None
db_init = False

def db_connected():
  if not db_init:
    return False
  try:
      dbconnector.ping()
  except:
      return False
  return True

def db_disconnect():
  dbconnector.close()
  db_init = False

def db_connect():
  global dbconnector
  global db
  global db_init
  if not db_connected():
    try:
      dbconnector = mariadb.connect(
        user=db_user,
        password=db_pass,
        host=db_host,
        port=int(db_port),
        database=db_name,
        autocommit=True
      )
    except mariadb.Error as e:
      print(f"Error connecting to MariaDB Platform: {e}")
      return False
    else:
      db = dbconnector.cursor()
      db_init = True
  return True

def db_exec(*args):
  if db_connect():
    try:
      db.execute(*args)
      return list(db.fetchall())
    except mariadb.Error as e:
      for e_msg in e.args:
        if e_msg == "Cursor doesn't have a result set":
          return list()
      print(f"Error while executing MariaDB SQL Query: {e}")
      raise e from None
  raise mariadb.Error(f"Can't connect to server on '{db_host}'")

def check_missing_table_or_function():
  return len(db_exec(f"SHOW TABLES LIKE '{TABLE_NAME}'")) == 0 or len(db_exec(f"SHOW FUNCTION STATUS LIKE '{FUNCTION_NAME}'")) == 0

def get_redirects():
  return db_exec(f"SELECT * FROM {TABLE_NAME}")

def resp_suc(msg):
  return {'result': "success", 'message': msg}

def resp_err(msg):
  return {'result': "error", 'message': msg}

def db_check(func):
  def inner(*args, **kwargs):
    if not db_connect(): return render_template('db_error.html', database_name=db_name, database_user=db_user)
    elif check_missing_table_or_function(): return render_template('db_init.html', database_name=db_name, table_name=TABLE_NAME, function_name=FUNCTION_NAME)
    else: return func(*args, **kwargs)
  return inner

@auth.verify_password
def verify_password(username, password):
  if username in http_users and check_password_hash(http_users.get(username), password):
    return username

@app.route('/config', methods=['POST'])
@auth.login_required
def config():
  if not db_connect(): return resp_err("Database connection could not be established.")
  req = request.json
  if req['action'] == "init":
    if not check_missing_table_or_function(): return resp_err("Database is already initialized.")
    db_exec(f"CREATE TABLE IF NOT EXISTS {TABLE_NAME} (id VARCHAR(32) NOT NULL, url VARCHAR({MAX_URL_LENGTH}) NOT NULL, new_win BOOLEAN NOT NULL, PRIMARY KEY (id)) ENGINE = InnoDB")
    db_exec(f"CREATE FUNCTION IF NOT EXISTS {FUNCTION_NAME}() RETURNS CHAR(32) BEGIN RETURN LOWER(CONCAT(HEX(RANDOM_BYTES(4)), HEX(RANDOM_BYTES(2)), '4', SUBSTR(HEX(RANDOM_BYTES(2)), 2, 3), HEX(FLOOR(ASCII(RANDOM_BYTES(1)) / 64) + 8), SUBSTR(HEX(RANDOM_BYTES(2)), 2, 3), hex(RANDOM_BYTES(6)))); END;")
    return resp_suc("Database is now initialized and ready.") if not check_missing_table_or_function() else resp_err("Database could not be initialized.")
  ks = req.keys()
  if 'action' not in ks:
    return resp_err("No action was requested.")
  if req['action'] == "new":
    if 'url' not in ks or 'new_win' not in ks: return resp_err
    if len(req['url']) > MAX_URL_LENGTH or str(req['new_win']).lower() not in ["true", "false", "1", "0"]: return resp_err
    suc = False
    # TODO remove suc
    res, suc = db_exec(f"INSERT INTO test VALUES({FUNCTION_NAME}(), ?, ?)", (req['url'], req['new_win']))
    return resp_suc if suc else resp_err
  if req['action'] == "edit":
    if 'id' not in ks or 'url' not in ks or 'new_win' not in ks: return resp_err
    if len(req['url']) > MAX_URL_LENGTH or str(req['new_win']).lower() not in ["true", "false", "1", "0"]: return resp_err
    # TODO remove suc
    res, suc = db_exec(f"UPDATE {TABLE_NAME} SET url = ?, new_win = ? WHERE id = ?", (req['url'], req['new_win'], req['id']))
    return resp_suc if suc else resp_err
  if req['action'] == "delete":
    if 'id' not in ks: return resp_err
    # TODO remove suc
    res, suc = db_exec(f"DELETE FROM {TABLE_NAME} WHERE id = ?", (req['id'],))
    return resp_suc if suc else resp_err
  return resp_err

@app.route('/r/<path:id>', methods=['GET'])
# TODO rename link to redir
def link(id):
  res = db_exec(f"SELECT id, url, new_win FROM {TABLE_NAME} WHERE id = ?", (id,))
  if len(res) == 0: abort(404)
  url = res[0][1]
  new_win = res[0][2]
  if new_win: return render_template('link_new_win.html', link=url)
  else: return render_template('link_same_win.html', link=url)

@app.route('/', endpoint='index')
@auth.login_required
@db_check
def index():
  redirects = get_redirects()
  return render_template('home.html', redirects=redirects)

@app.route('/add', endpoint='add')
@auth.login_required
@db_check
def add():
  pass

@app.route('/edit', endpoint='edit')
@auth.login_required
@db_check
def edit():
  pass

@app.route('/delete', endpoint='delete')
@auth.login_required
@db_check
def delete():
  pass

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port="81")