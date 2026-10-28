FROM debian:13-slim AS base
RUN apt update && apt install -y curl
RUN curl -Lo /usr/local/bin/imaptest https://github.com/dovecot/imaptest/releases/download/latest/imaptest-$(uname -m)-debian-13
RUN chmod +x /usr/local/bin/imaptest
FROM debian:13-slim AS final
RUN apt update && apt install -y libpcre2-32-0 && apt clean all
COPY --link --from=base /usr/local/bin/imaptest /usr/local/bin/imaptest
COPY build/tests /usr/local/share/imaptest/tests
USER mail
ENTRYPOINT ["/usr/local/bin/imaptest"]
