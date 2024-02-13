FROM gcr.io/distroless/static:latest
COPY dummy_minecraft_server /
ENTRYPOINT ["/dummy_minecraft_server"]
