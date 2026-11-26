terraform {
  required_version = ">= 1.10.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  backend "s3" {
    bucket       = "tf-state-somesh-081298790381"
    key          = "devsecops/terraform.tfstate"
    region       = "ap-southeast-2"
    encrypt      = true
    use_lockfile = true
  }
}

# 1. Configure the AWS Provider (Validated by CKV_CUSTOM_1)
provider "aws" {
  region = "ap-southeast-2"
}

# 2. Create the Virtual Private Cloud (VPC)
resource "aws_vpc" "main_vpc" {
  # checkov:skip=CKV2_AWS_11:VPC Flow Logs omitted to avoid paid CloudWatch/KMS resources in student lab
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name        = "DevSecOps-VPC"
    Owner       = "Somesh-Sharma"
    Environment = "DevSecOps-Lab"
  }
}

# 3. Lock Down the Default Security Group (Fixes CKV2_AWS_12)
resource "aws_default_security_group" "default" {
  vpc_id = aws_vpc.main_vpc.id

  tags = {
    Name        = "DevSecOps-Default-SG-Restricted"
    Owner       = "Somesh-Sharma"
    Environment = "DevSecOps-Lab"
  }
}

# 4. Create a Public Subnet (Fixes CKV_AWS_130)
resource "aws_subnet" "public_subnet" {
  vpc_id                  = aws_vpc.main_vpc.id
  cidr_block              = "10.0.1.0/24"
  map_public_ip_on_launch = false
  availability_zone       = "ap-southeast-2a"

  tags = {
    Name        = "Public-Subnet"
    Owner       = "Somesh-Sharma"
    Environment = "DevSecOps-Lab"
  }
}

# 5. Create a Private Subnet (For isolated database tier)
resource "aws_subnet" "private_subnet" {
  vpc_id            = aws_vpc.main_vpc.id
  cidr_block        = "10.0.2.0/24"
  availability_zone = "ap-southeast-2a"

  tags = {
    Name        = "Private-Subnet"
    Owner       = "Somesh-Sharma"
    Environment = "DevSecOps-Lab"
  }
}

# 6. Create an Internet Gateway
resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.main_vpc.id

  tags = {
    Name        = "Main-IGW"
    Owner       = "Somesh-Sharma"
    Environment = "DevSecOps-Lab"
  }
}

# 7. Create a Route Table and Link it to the Internet Gateway
resource "aws_route_table" "public_rt" {
  vpc_id = aws_vpc.main_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }

  tags = {
    Name        = "Public-RouteTable"
    Owner       = "Somesh-Sharma"
    Environment = "DevSecOps-Lab"
  }
}

# 8. Associate the Route Table with the Public Subnet
resource "aws_route_table_association" "public_rt_assoc" {
  subnet_id      = aws_subnet.public_subnet.id
  route_table_id = aws_route_table.public_rt.id
}

# 9. Zero-Trust Web-Tier Security Group (HTTPS 443 In -> Private DB Subnet 3306 Out Only)
resource "aws_security_group" "web_tier_sg" {
  # checkov:skip=CKV2_AWS_5:Zero-Trust SG blueprint pre-provisioned without paid EC2 compute instances
  name        = "devsecops-web-tier-sg"
  description = "Zero-Trust Web Tier: allows HTTPS 443 inbound and restricts outbound to DB subnet port 3306"
  vpc_id      = aws_vpc.main_vpc.id

  ingress {
    description = "Allow encrypted HTTPS traffic from internet"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "Allow outbound MySQL queries only to Private Subnet"
    from_port   = 3306
    to_port     = 3306
    protocol    = "tcp"
    cidr_blocks = [aws_subnet.private_subnet.cidr_block]
  }

  tags = {
    Name        = "ZeroTrust-Web-Tier-SG"
    Owner       = "Somesh-Sharma"
    Environment = "DevSecOps-Lab"
  }
}

# 10. Zero-Trust Database-Tier Security Group (Accepts Port 3306 ONLY from Web-Tier SG)
resource "aws_security_group" "db_tier_sg" {
  # checkov:skip=CKV2_AWS_5:Zero-Trust SG blueprint pre-provisioned without paid RDS database instances
  name        = "devsecops-db-tier-sg"
  description = "Zero-Trust Database Tier: isolated from internet, accepts port 3306 strictly from Web-Tier SG"
  vpc_id      = aws_vpc.main_vpc.id

  ingress {
    description     = "Allow MySQL traffic strictly from Web-Tier Security Group"
    from_port       = 3306
    to_port         = 3306
    protocol        = "tcp"
    security_groups = [aws_security_group.web_tier_sg.id]
  }

  tags = {
    Name        = "ZeroTrust-DB-Tier-SG"
    Owner       = "Somesh-Sharma"
    Environment = "DevSecOps-Lab"
  }
}
