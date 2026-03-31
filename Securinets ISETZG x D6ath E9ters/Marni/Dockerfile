FROM ubuntu:latest

RUN apt-get update && apt-get install -y socat
RUN apt-get install -y lib32z1 libseccomp-dev

WORKDIR /ctf

RUN useradd -m user

COPY main flag.txt ./

RUN chown -R root:user /ctf && \
    chmod 750 /ctf/main  && \
    chmod 440 /ctf/flag.txt

USER user

EXPOSE 5005

CMD socat TCP-LISTEN:5005,reuseaddr,fork EXEC:'timeout 120 ./main

