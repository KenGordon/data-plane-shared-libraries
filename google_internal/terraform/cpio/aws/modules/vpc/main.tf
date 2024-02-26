/**
 * Copyright 2023 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

################################################################################
# The main VPC.
################################################################################
resource "aws_vpc" "vpc" {
  cidr_block           = var.cidr_blocks
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "${var.service}-${var.environment}-vpc"
  }
}

################################################################################
# Create subnets publically and privately inside the VPC.
################################################################################

# Get information about available AZs.
data "aws_availability_zones" "azs" {
  state = "available"
}

# Create public subnets for connecting to instances in private subnets.
resource "aws_subnet" "public_subnet" {
  count                   = length(data.aws_availability_zones.azs.names)
  cidr_block              = cidrsubnet(aws_vpc.vpc.cidr_block, 4, count.index)
  vpc_id                  = aws_vpc.vpc.id
  availability_zone       = data.aws_availability_zones.azs.names[count.index]
  map_public_ip_on_launch = true

  tags = {
    Name = "${var.service}-${var.environment}-public-subnet${count.index}"
  }
}

# Create private subnets where instances will be launched.
resource "aws_subnet" "private_subnet" {
  count                   = length(data.aws_availability_zones.azs.names)
  cidr_block              = cidrsubnet(aws_vpc.vpc.cidr_block, 4, 15 - count.index)
  vpc_id                  = aws_vpc.vpc.id
  availability_zone       = data.aws_availability_zones.azs.names[count.index]
  map_public_ip_on_launch = false

  tags = {
    Name = "${var.service}-${var.environment}-private-subnet${count.index}"
  }
}

################################################################################
# Components for public subnets to provide the VPC access to the internet.
################################################################################
resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.vpc.id

  tags = {
    Name = "${var.service}-${var.environment}-igw"
  }
}

resource "aws_route_table" "public_rt" {
  vpc_id = aws_vpc.vpc.id

  tags = {
    Name = "${var.service}-${var.environment}-public-rt"
  }
}

resource "aws_route" "public_route" {
  route_table_id         = aws_route_table.public_rt.id
  gateway_id             = aws_internet_gateway.igw.id
  destination_cidr_block = "0.0.0.0/0"

  depends_on = [
    aws_internet_gateway.igw
  ]
}

# Associate the public subnet with the public route table.
resource "aws_route_table_association" "public_rt_assoc" {
  count          = length(aws_subnet.public_subnet)
  subnet_id      = aws_subnet.public_subnet[count.index].id
  route_table_id = aws_route_table.public_rt.id
}

################################################################################
# Create private route tables required for gateway endpoints.
################################################################################
resource "aws_eip" "private_subnet_eip" {
  count = length(aws_subnet.private_subnet)
  vpc   = true
  depends_on = [
    aws_internet_gateway.igw
  ]
}

resource "aws_nat_gateway" "nat_gateway" {
  count         = length(aws_subnet.private_subnet)
  subnet_id     = aws_subnet.public_subnet[count.index].id
  allocation_id = aws_eip.private_subnet_eip[count.index].id

  depends_on = [
    aws_internet_gateway.igw
  ]

  tags = {
    Name = "${var.service}-${var.environment}-nat-gw${count.index}"
  }
}

resource "aws_route_table" "private_rt" {
  count  = length(aws_subnet.private_subnet)
  vpc_id = aws_vpc.vpc.id

  tags = {
    Name = "${var.service}-${var.environment}-private-rt${count.index}"
  }
}

resource "aws_route" "private_route" {
  count                  = length(aws_subnet.private_subnet)
  route_table_id         = aws_route_table.private_rt[count.index].id
  nat_gateway_id         = aws_nat_gateway.nat_gateway[count.index].id
  destination_cidr_block = "0.0.0.0/0"
}

resource "aws_route_table_association" "private_rt_assoc" {
  count          = length(aws_subnet.private_subnet)
  route_table_id = aws_route_table.private_rt[count.index].id
  subnet_id      = aws_subnet.private_subnet[count.index].id
}
