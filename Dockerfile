FROM golang:1.15-alpine as builder

# Create the user and group files that will be used in the running container to
# run the process as an unprivileged user.
RUN mkdir /user && \
    echo 'nobody:x:65534:65534:nobody:/:' > /user/passwd && \
    echo 'nobody:x:65534:' > /user/group

# Git is required for fetching the dependencies, and ca-certificates are used to make outbound HTTPS connections with
# a valid CA certificate pool
RUN apk add --no-cache ca-certificates git

# Set the working directory to where we would build the tool
WORKDIR /go/src/github.com/leebrotherston/tlsGuard

# Fetch dependencies first; they are less susceptible to change on every build and will therefore be cached for
# speeding up the next build
COPY ./go.mod ./go.sum ./
RUN go mod download

# Import the code from the context
COPY . .

# Build the executable to `/tlsGuard`
RUN CGO_ENABLED=0 go build -installsuffix 'static' -ldflags "-s -w" -o /tlsGuard ./cmd/

# Final stage: the running container
FROM scratch as final

# Expose port 8000 for HTTP health check (located at "/health")
EXPOSE 443/tcp

# Import the user and group files from the first stage.
COPY --from=builder /user/group /user/passwd /etc/

# Import the Certificate-Authority certificates for enabling HTTPS.
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Import the tlsGuard binary to the /bin directory
COPY --from=builder /tlsGuard /bin/tlsGuard

# Perform any further action as an unprivileged user.
USER nobody:nobody

# Run tlsGuard
ENTRYPOINT ["/bin/tlsGuard"]