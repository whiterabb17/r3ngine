# Multi-target bake for the three role images.
# Usage: docker buildx bake -f docker-bake.hcl
#        make build-app-images

variable "WEB_IMAGE" {
  default = "r3ngine-web:local"
}

variable "PYTHON_IMAGE" {
  default = "r3ngine-python:local"
}

variable "GO_IMAGE" {
  default = "r3ngine-go-executor:local"
}

group "default" {
  targets = ["web", "python-orchestrator", "go-executor"]
}

target "web" {
  context    = "."
  dockerfile = "docker/web/Dockerfile"
  target     = "web"
  tags       = ["${WEB_IMAGE}"]
}

target "python-orchestrator" {
  context    = "."
  dockerfile = "docker/web/Dockerfile"
  target     = "python-orchestrator"
  tags       = ["${PYTHON_IMAGE}"]
}

target "go-executor" {
  context    = "."
  dockerfile = "docker/web/Dockerfile"
  target     = "go-executor"
  tags       = ["${GO_IMAGE}"]
}
