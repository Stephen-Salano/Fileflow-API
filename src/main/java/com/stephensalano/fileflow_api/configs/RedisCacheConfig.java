package com.stephensalano.fileflow_api.configs;

import com.fasterxml.jackson.annotation.JsonIdentityInfo;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.fasterxml.jackson.annotation.ObjectIdGenerators;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.jsontype.BasicPolymorphicTypeValidator;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.stephensalano.fileflow_api.entities.Account;
import com.stephensalano.fileflow_api.entities.User;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.cache.RedisCacheConfiguration;
import org.springframework.data.redis.serializer.GenericJackson2JsonRedisSerializer;
import org.springframework.data.redis.serializer.RedisSerializationContext;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

@Configuration
@EnableCaching
public class RedisCacheConfig {

    // Mixins to handle circular dependencies with @JsonIdentityInfo.
    // This is superior to @JsonManagedReference/@JsonBackReference as it preserves the object graph.
    @JsonIdentityInfo(generator = ObjectIdGenerators.PropertyGenerator.class, property = "id")
    private abstract static class AccountIdentityMixin {}

    // This mixin handles the User entity's circular reference and tells Jackson how to handle
    // Hibernate's specific collection types during serialization and deserialization.
    @JsonIdentityInfo(generator = ObjectIdGenerators.PropertyGenerator.class, property = "id")
    public abstract static class UserIdentityMixin {
        @JsonSerialize(as = ArrayList.class) // Serialize as a standard ArrayList
        @JsonDeserialize(as = ArrayList.class) // Deserialize as a standard ArrayList
        public abstract List<Account> getAccounts();
    }

    /**
     * Shared ObjectMapper for Redis serialization/deserialization.
     * - Registers JavaTimeModule for java.time types
     * - Adds mixins for Account/User to avoid cycles
     * - Activates polymorphic typing using PROPERTY style (stable & readable)
     */
    @Bean
    public ObjectMapper redisObjectMapper() {
        ObjectMapper mapper = new ObjectMapper();
        mapper.registerModule(new JavaTimeModule());

        // add mixins
        mapper.addMixIn(Account.class, AccountIdentityMixin.class);
        mapper.addMixIn(User.class, UserIdentityMixin.class);

        // Polymorphic type validator: keep this as narrow as you can.
        BasicPolymorphicTypeValidator ptv = BasicPolymorphicTypeValidator.builder()
                // For security, only allow deserialization of classes from your application's base package.
                .allowIfBaseType("com.stephensalano.fileflow_api")
                // Also allow Hibernate's collection types, which are used for lazy loading.
                // This is a safe compromise to prevent deserialization errors for JPA-managed collections.
                .allowIfSubType("org.hibernate.collection")
                .build();

        // Use PROPERTY style so Jackson writes a @class (or similar) field inside the object.
        mapper.activateDefaultTyping(ptv, ObjectMapper.DefaultTyping.NON_FINAL, JsonTypeInfo.As.PROPERTY);

        return mapper;
    }

    /**
     * Redis cache configuration for Spring Cache (@Cacheable etc.)
     * Uses the shared ObjectMapper for value serialization.
     */
    @Bean
    public RedisCacheConfiguration cacheConfiguration(ObjectMapper redisObjectMapper) {
        GenericJackson2JsonRedisSerializer jsonSerializer = new GenericJackson2JsonRedisSerializer(redisObjectMapper);

        return RedisCacheConfiguration.defaultCacheConfig()
                .entryTtl(Duration.ofMinutes(60))
                .disableCachingNullValues()
                .serializeValuesWith(RedisSerializationContext.SerializationPair.fromSerializer(jsonSerializer));
    }
}