FROM debian:12-slim
COPY dummy_minecraft_server /
ENTRYPOINT ["/dummy_minecraft_server"]
