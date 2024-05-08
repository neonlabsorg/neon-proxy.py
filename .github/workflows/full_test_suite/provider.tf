terraform {
  required_providers {
    hcloud = {
      source  = "hetznercloud/hcloud"
      version = "1.45.0"
    }
  }

  backend "s3" {
    // Must be set from environment
  }
}

provider "hcloud" {
  # Configuration options
}
