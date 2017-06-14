import redis

import hubscrub.config as config


def init_redis_client():
    redis_client = redis.StrictRedis(
        host=config.redis_host,
        port=config.redis_port,
        db=0,
        encoding='utf-8',
        decode_responses=True
    )

    return redis_client
