FROM ubuntu:latest

RUN apt-get update && \
    apt-get install -y socat lib32z1 libseccomp-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /ctf

RUN useradd -m -s /bin/false user
COPY main flag.txt ./

RUN chown -R root:user /ctf && \
    chmod 750 /ctf/main && \
    chmod 440 /ctf/flag.txt && \
    chmod 750 /bin/sh && \
    chown root:root /bin/sh && \
    [ -f /bin/bash ] && chmod 750 /bin/bash && chown root:root /bin/bash || true && \
    [ -f /bin/dash ] && chmod 750 /bin/dash && chown root:root /bin/dash || true && \
    rm -f /bin/rbash /usr/bin/zsh /usr/bin/tmux /usr/bin/screen /usr/bin/script && \
    echo 'PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin' > /etc/environment

USER user

RUN [ ! -x "/bin/sh" ] || [ ! -r "/bin/sh" ] || exit 1

EXPOSE 10002

CMD socat TCP-LISTEN:10002,reuseaddr,fork EXEC:'timeout 200 ./main'
