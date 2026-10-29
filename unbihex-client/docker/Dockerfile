# The Unbihex console client in a container: QNAP Container Station, Synology,
# any Docker host. Build it next to the release binary for the NAS's processor
# (unbihex-cli-<version>-linux-x86_64, -aarch64 or -armv7, renamed to unbihex-cli):
#
#   docker build -t unbihex-cli .
#   docker run --rm -v /share/Container/unbihex:/data unbihex-cli add 'https://subscription'
#   docker run -d --name unbihex --restart unless-stopped \
#     -v /share/Container/unbihex:/data -p 10808:10808 -p 10809:10809 unbihex-cli
#   docker logs unbihex          # the LAN login and password
#
# The binary is static and carries its own CA roots, so the image needs nothing else.
FROM scratch
COPY unbihex-cli /unbihex-cli
ENV UNBIHEX_DIR=/data
VOLUME /data
ENTRYPOINT ["/unbihex-cli"]
CMD ["connect", "--lan"]
