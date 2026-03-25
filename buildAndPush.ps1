# localhost
podman build -t pgphantom:0.1.0 .

# production 
podman login ghcr.io -u (username)
# paste PAT from GitHub secrets here


podman build -t ghcr.io/cloudfy/pgphantom:0.1.0 .
podman push ghcr.io/cloudfy/pgphantom:0.1.0
