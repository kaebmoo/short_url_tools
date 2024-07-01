import redis

def redis_connection():
    try:
        global r
        with redis.Redis(host="localhost", port=6379, db=1) as r:
            print("Redis connected.")
    except redis.exceptions.RedisError as e:
        print(e)

def redis_query(url):
    try:
        res = r.sismember("blacklist:url", url)
        if res == 0:
            print("no member")
            res = r.smembers("blacklist:url")
            print(res)
            print()
        else:
            print(res)
            print("found : ", url)
    except redis.exceptions.RedisError as e:
        print(e)

def redis_add(key, member):
    try:
        res = r.sadd(key, member)
        return res
    except redis.exceptions.RedisError as e:
        print(e)


redis_connection()
# res1 = redis_add("blacklist:url", "www.google.com")
# res2 = redis_add("blacklist:url", "www.ntplc.co.th")
# print(res1)
# print(res2)

redis_query("www.google.com")

