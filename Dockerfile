FROM gcr.io/distroless/static:latest
COPY dummy_minecraft_server /
COPY dummy_minecraft_server.toml /
ENTRYPOINT ["/dummy_minecraft_server"]
