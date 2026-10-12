packer {
  required_plugins {
    docker = {
      version = ">= 1.0.8"
      source  = "github.com/hashicorp/docker"
    }
  }
}

variable "image_tag" {
  type    = string
  default = "secureship-base:latest"
}

source "docker" "ubuntu" {
  image  = "ubuntu:22.04"
  commit = true
}

build {
  name    = "secureship-machine-image"
  sources = ["source.docker.ubuntu"]

  provisioner "shell" {
    inline = [
      "apt-get update",
      "apt-get install -y python3 python3-pip curl git",
      "mkdir -p /opt/secureship",
      "echo 'SecureShip Base Image Configured' > /opt/secureship/version.txt"
    ]
  }

  post-processor "docker-tag" {
    repository = "secureship-base"
    tags       = ["latest", "0.1.0"]
  }
}
