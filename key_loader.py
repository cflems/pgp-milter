import config
import mysql.connector as mysql
import pgpy

def load_keys(addrs: list[str]) -> list[pgpy.PGPKey]:
  if len(addrs) < 1:
    return []

  db = mysql.connect(**config.db_config)
  try:
    stmt = db.cursor()
  except Exception as e:
    db.close()
    raise e
  
  try:
    stmt.execute(\
      format_multiquery(config.key_loader_query, len(addrs)), \
      tuple(addrs) \
    )
    
    keys = {}
    for (keyfpr, keydata) in stmt:
      if keyfpr in keys:
        continue
      key = pgpy.PGPKey()
      try:
        key.parse(keydata)
      except:
        continue

    return list(keys.values())
  finally:
    stmt.close()
    db.close()

def format_multiquery(query: str, n_items: int) -> str:
  return query % (', '.join(['%s'] * n_items),)
