var builder = DistributedApplication.CreateBuilder(args);

var postgres = builder.AddPostgres("postgres")
    .WithDataVolume("veil-postgres-data")
    .WithPgWeb();
var database = postgres.AddDatabase("veil");

var redis = builder.AddRedis("redis")
    .WithDataVolume("veil-redis-data")
    .WithRedisInsight();

builder.AddProject<Projects.Veil_Api>("api")
    .WithReference(database, connectionName: "Postgres")
    .WithReference(redis, connectionName: "Redis")
    .WaitFor(database)
    .WaitFor(redis)
    .WithEnvironment("Database__MigrateOnStartup", "true")
    .WithEnvironment("OpenApi__Enabled", "true")
    .WithHttpHealthCheck("/health")
    .WithExternalHttpEndpoints();

builder.Build().Run();
