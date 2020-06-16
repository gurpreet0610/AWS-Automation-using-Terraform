provider "aws" {
	region = "ap-south-1"
	profile = "gurpreetaws"
}

# Creating key_pair for SSH in AWS instance

resource "tls_private_key" "createkey" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "aws_key_pair" "generated_key" {
  key_name   = "ec2_key"
  public_key = tls_private_key.createkey.public_key_openssh
}

resource "null_resource" "savekey"  {
  depends_on = [
    tls_private_key.createkey,
  ]
	provisioner "local-exec" {
	    command = "echo  '${tls_private_key.createkey.private_key_pem}' > ec2_key.pem"
  	}
}

# Creating Security Group
resource "aws_security_group" "allow_webservices_and_SSH" {
  name        = "allow_webservices_and_SSH"
  description = "Allow webservices and ssh inbound traffic"
  # allow ingress of port 80
  ingress {
    description = "Allow HTTP"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  # allow ingress of port 22
  ingress { 
    description = "Allow SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  } 

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "allow_webservices_and_SSH"
  }
}


# Creating AWS EC2 Instance with previously created key pair and security group

resource "aws_instance" "webserver" {
  ami           = "ami-005956c5f0f757d37"
  instance_type = "t2.micro"
  key_name = aws_key_pair.generated_key.key_name
  security_groups = [ "${aws_security_group.allow_webservices_and_SSH.name}" ]

  connection {
    type     = "ssh"
    user     = "ec2-user"
    private_key = tls_private_key.createkey.private_key_pem
    host     = aws_instance.webserver.public_ip
  }

  provisioner "remote-exec" {
    inline = [
    "sudo yum update -y",
    "sudo yum install git -y",
    "sudo yum install docker -y",
    "sudo service docker start",
    "sudo usermod -a -G docker ec2-user",
    "sudo docker pull httpd",
    "mkdir webserver_code"
    ]
  }

  tags = {
    Name = "website_server1"
  }

}

# Creating EBS volumes and Attach to EC2 Instance

resource "aws_ebs_volume" "myebs" {
  availability_zone = aws_instance.webserver.availability_zone
  size              = 1
  tags = {
    Name = "servervol"
  }
}

resource "aws_volume_attachment" "attach_ebs" {
  device_name = "/dev/sdh"
  volume_id   = aws_ebs_volume.myebs.id
  instance_id = aws_instance.webserver.id
  force_detach = true
}

resource "null_resource" "AttachmentRemoteExecution"  {

depends_on = [
    aws_volume_attachment.attach_ebs,
  ]

  connection {
    type     = "ssh"
    user     = "ec2-user"
    private_key = tls_private_key.createkey.private_key_pem
    host     = aws_instance.webserver.public_ip
  }

provisioner "remote-exec" {
    inline = [
      "ls",
      "sudo mkfs.ext4  /dev/xvdh",
      "sudo mount  /dev/xvdh  ~/webserver_code",
    ]
  }
}
# Storing IP address in file
resource "null_resource" "getIp"  {
	provisioner "local-exec" {
	    command = "echo  ${aws_instance.webserver.public_ip} > publicip.txt"
  	}
}

# pulling github repository to EC2 Instance

resource "null_resource" "getting_data"  {

depends_on = [
    null_resource.AttachmentRemoteExecution,
  ]
  connection {
    type     = "ssh"
    user     = "ec2-user"
    private_key = tls_private_key.createkey.private_key_pem
    host     = aws_instance.webserver.public_ip
  }

provisioner "remote-exec" {
    inline = [
      "cd webserver_code",
      "sudo rm -rvf ./*",
      "sudo git clone https://github.com/gurpreet0610/testing-webapp.git ."
    ]
  }
}

# Creating S3 bucket and uploading media files

resource "aws_s3_bucket" "gurpreetassets" {
  bucket = "gurpreetassets" 
  acl    = "private"
  region = "ap-south-1"
}


resource "null_resource" "upload_to_s3" {
  depends_on = [
    null_resource.getting_data
  ]

  provisioner "local-exec" {
    command = "git clone https://github.com/gurpreet0610/testing-webapp.git ./git_data && aws s3 sync ./git_data/images s3://${aws_s3_bucket.gurpreetassets.bucket}" 
  }
}

resource "aws_cloudfront_origin_access_identity" "origin_access_identity" {
  comment = "My origin access identity"
}


data "aws_iam_policy_document" "bucket_policy_data" {
  statement {
    actions = ["s3:GetObject"]
    principals {
      type        = "AWS"
      identifiers = ["${aws_cloudfront_origin_access_identity.origin_access_identity.iam_arn}"]
    }
    resources = ["${aws_s3_bucket.gurpreetassets.arn}/*"]
  }
}

resource "aws_s3_bucket_policy" "bucket_policy" {
  bucket = aws_s3_bucket.gurpreetassets.id
  policy = data.aws_iam_policy_document.bucket_policy_data.json
}

# Cloud Front service
resource "aws_cloudfront_distribution" "myCloudfront" {
  depends_on = [
    aws_s3_bucket.gurpreetassets
  ]
    origin {
        domain_name = aws_s3_bucket.gurpreetassets.bucket_domain_name
        origin_id   = aws_s3_bucket.gurpreetassets.id
        s3_origin_config {
      origin_access_identity = aws_cloudfront_origin_access_identity.origin_access_identity.cloudfront_access_identity_path
    }
    }
       
    enabled = true

    default_cache_behavior {
        allowed_methods = [ "GET", "HEAD", "OPTIONS"]
        cached_methods = [ "GET", "HEAD", "OPTIONS"]
        target_origin_id = aws_s3_bucket.gurpreetassets.id

        # Forward all query strings, cookies and headers
        forwarded_values {
            query_string = false
        
            cookies {
               forward = "none"
            }
        }
        viewer_protocol_policy = "allow-all"
        min_ttl = 0
        default_ttl = 3600
        max_ttl = 86400
    }
    
    restrictions {
        geo_restriction {
            # type of restriction, blacklist, whitelist or none
            restriction_type = "none"
        }
    }

    # SSL certificate for the service.
    viewer_certificate {
        cloudfront_default_certificate = true
    }
}

output dname {
  value = ["${aws_cloudfront_distribution.myCloudfront.domain_name}"]
}

# Updating path inside the code -> images -> Bucket_domain_name

resource "null_resource" "updating_file_path_and_launching_server"  {

depends_on = [
    null_resource.upload_to_s3,
    null_resource.getting_data
  ]


  connection {
    type     = "ssh"
    user     = "ec2-user"
    private_key = tls_private_key.createkey.private_key_pem
    host     = aws_instance.webserver.public_ip
  }

provisioner "remote-exec" {
    inline = [
      "echo hello Servers",
      "sudo sed -i 's/images/https:\\/\\/${aws_cloudfront_distribution.myCloudfront.domain_name}/g' ~/webserver_code/assets/js/main.js",
      "sudo docker run -v ~/webserver_code:/usr/local/apache2/htdocs/ -p 80:80 -d --name my_server httpd"
      ]
  }
}


resource "null_resource" "nulllocal1"  {


depends_on = [
    null_resource.updating_file_path_and_launching_server,
  ]

	provisioner "local-exec" {
	    command = "google-chrome  ${aws_instance.webserver.public_ip}"
  	}
}

