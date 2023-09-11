# syntax=docker/dockerfile:1
FROM alpine:latest AS html-stage

WORKDIR /app

RUN mkdir /app/html
COPY html/ /app/html

FROM golang:1.21.1 AS build-stage

WORKDIR /app

COPY go.mod go.sum /app/
RUN go mod download

COPY . /app/
RUN rm -rf /app/html/

RUN CGO_ENABLED=0 GOOS=linux go build -o auth_system

FROM alpine:latest

WORKDIR /app

COPY --from=build-stage /app/auth_system /auth_system
COPY --from=html-stage /app/html/ /html

COPY app.docker.env /app.env

EXPOSE 9000 

CMD ["/auth_system"]
