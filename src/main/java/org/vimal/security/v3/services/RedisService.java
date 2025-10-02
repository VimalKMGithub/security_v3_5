package org.vimal.security.v3.services;

import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.List;
import java.util.Objects;
import java.util.Set;

@Service
@RequiredArgsConstructor
public class RedisService {
    private static final Duration DEFAULT_TIME_TO_LIVE = Duration.ofMinutes(5);
    private final RedisTemplate<String, String> redisTemplate;

    public void save(String key,
                     String value) {
        save(
                key,
                value,
                DEFAULT_TIME_TO_LIVE
        );
    }

    public void save(String key,
                     String value,
                     Duration timeToLive) {
        redisTemplate.opsForValue()
                .set(
                        key,
                        value,
                        timeToLive
                );
    }

    public String get(String key) {
        return redisTemplate.opsForValue()
                .get(key);
    }

    public Long getTtl(String key) {
        return redisTemplate.getExpire(key);
    }

    public List<String> getAll(Set<String> keys) {
        return redisTemplate.opsForValue()
                .multiGet(keys);
    }

    public void delete(String key) {
        redisTemplate.delete(key);
    }

    public void deleteAll(Set<String> keys) {
        redisTemplate.delete(keys);
    }

    public Boolean addZSetMember(String key,
                                 String member,
                                 double score,
                                 Duration timeToLive) {
        Boolean isAdded = redisTemplate.opsForZSet()
                .add(
                        key,
                        member,
                        score
                );
        redisTemplate.expire(
                key,
                timeToLive
        );
        return isAdded;
    }

    public void updateZSetMemberScore(String key,
                                      String member,
                                      double score) {
        redisTemplate.opsForZSet()
                .add(
                        key,
                        member,
                        score
                );
    }

    public Set<String> getAllZSetMembers(String key) {
        return redisTemplate.opsForZSet()
                .range(
                        key,
                        0,
                        -1
                );
    }

    public void removeZSetMember(String key,
                                 String member) {
        redisTemplate.opsForZSet()
                .remove(
                        key,
                        member
                );
    }

    public Double getZSetMemberScore(String key,
                                     String member) {
        return redisTemplate.opsForZSet()
                .score(
                        key,
                        member
                );
    }

    public void flushDb() {
        Objects.requireNonNull(redisTemplate.getConnectionFactory())
                .getConnection()
                .serverCommands()
                .flushDb();
    }
}
