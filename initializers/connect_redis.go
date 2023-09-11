package initializers

import (
	"context"
	"fmt"

	"github.com/redis/go-redis/v9"
)

var (
	RedisClient *redis.Client
	ctx         context.Context
)

func ConnectRedis(config *Config) error {
	ctx = context.TODO()

	RedisClient = redis.NewClient(&redis.Options{
		Addr: config.RedisUrl,
	})

	if _, err := RedisClient.Ping(ctx).Result(); err != nil {
		return err
	}

	err := RedisClient.Set(ctx, "test", "test", 0).Err()
	if err != nil {
		return err
	}

	fmt.Println("✅ Redis client connected successfully...")
	return nil
}
