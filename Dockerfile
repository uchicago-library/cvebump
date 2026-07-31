FROM alpine:3.20 AS base

FROM base AS builder

RUN apk update && \
    apk upgrade && \
    apk add build-base --no-cache opam git

RUN addgroup ocamldev && adduser -G ocamldev -D ocamldev

USER ocamldev

RUN opam init --bare -a -y --disable-sandboxing \
    && opam update

RUN opam switch create default ocaml-base-compiler.5.2.0

WORKDIR /app

RUN mkdir ./app ./lib

COPY dune-project cvebump.opam ./

COPY app/* ./app

COPY lib/* ./lib

COPY test/* ./test

RUN opam repository add dldc https://dldc.lib.uchicago.edu/opam && \
    opam update && \
    eval $(opam env) && \
    opam install . --deps-only --yes

RUN opam exec -- dune build && \
    cp app/cvebump.exe /app

WORKDIR /app

CMD [ "app/cvebump.exe" ]
