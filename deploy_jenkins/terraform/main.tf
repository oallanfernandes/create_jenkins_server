terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 3.0"
    }
  }
}

# Configure the AWS Provider
provider "aws" {
  region = "us-east-1"
}

#Save state in S3 bucket#
terraform{
    backend "s3"{
      bucket = "l4c-terraform-prod"
      key    = "jenkins-server.tfstate"
      region = "us-east-1"
    }
}

resource "null_resource" "install_terraform" {
  depends_on      = [aws_instance.jenkins]
  provisioner "local-exec" {
      command     = "sleep 30 && ansible-playbook -i ${aws_instance.jenkins.public_dns}, install_terraform.yml"
      working_dir = "../ansible"  
  }
}

resource "null_resource" "install_jenkins" {
  depends_on      = [null_resource.install_terraform]
  provisioner "local-exec" {
      command     = "sleep 10 && ansible-playbook -i ${aws_instance.jenkins.public_dns}, install_jenkins.yml"
      working_dir = "../ansible"  
  }
}

resource "null_resource" "install_ansible" {
  depends_on      = [null_resource.install_jenkins]
  provisioner "local-exec" {
      command     = "sleep 10 && ansible-playbook -i ${aws_instance.jenkins.public_dns}, install_ansible.yml"
      working_dir = "../ansible"  
  }
}