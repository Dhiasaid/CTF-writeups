FROM ubuntu:latest

RUN apt-get update && apt-get install -y socat
RUN apt-get install -y lib32z1 libseccomp-dev

WORKDIR /ctf

RUN useradd -m user

COPY main flag.txt ./

RUN chown -R root:user /ctf && \
    chmod 750 /ctf/main && \
    chmod 440 /ctf/flag.txt

USER user

EXPOSE 10005

CMD socat TCP-LISTEN:10005,reuseaddr,fork EXEC:'timeout 200 ./main'
