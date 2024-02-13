FROM gcr.io/distroless/base-nossl:latest
COPY dummy_minecraft_server /
ENTRYPOINT ["/dummy_minecraft_server"]
