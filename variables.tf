
variable "region" {
  description = ""
  default = "ap-southeast-2"  
}
variable "environment" {
  description = ""
  default = "test"  
}

variable "project" {
  description = "project name"
  default = "istio-test"  
}

variable "OsVolume" {
  description = "volume size"
  default = 50 
}



variable "aws_amis" {
  description = "The AMI to use for setting up the instances."
  default = {
    # Ubuntu Xenial 20.04 LTS
    # default is list[0] ubuntu 20.04 LTS / golden ami is list[1]
    us-east-1      = ["ami-09e67e426f25ce0d7","ami-09e67e426f25ce0d7"]
    us-east-2      = ["ami-00399ec92321828f5","ami-00399ec92321828f5"]
    us-west-1      = ["ami-0d382e80be7ffdae5","ami-0d382e80be7ffdae5"]
    us-west-2      = ["ami-03d5c68bab01f3496","ami-03d5c68bab01f3496"]
    ap-south-1     = ["ami-0c1a7f89451184c8b","ami-0c1a7f89451184c8b"]
    ap-east-1      = ""
    ap-northeast-1 = ["ami-0df99b3a8349462c6","ami-0df99b3a8349462c6"]
    ap-northeast-2 = ["ami-04876f29fd3a5e8ba","ami-04876f29fd3a5e8ba"]
    ap-northeast-3 = ["ami-0001d1dd884af8872","ami-0001d1dd884af8872"]
    ap-southeast-1 = ["ami-0d058fe428540cd89","ami-0d058fe428540cd89"]
    ap-southeast-2 = ["ami-0567f647e75c7bc05","ami-0567f647e75c7bc05"]
    ca-central-1   = ["ami-0801628222e2e96d6","ami-0801628222e2e96d6"]
    eu-central-1   = ["ami-05f7491af5eef733a","ami-05f7491af5eef733a"]
    eu-west-1      = ["ami-0a8e758f5e873d1c1","ami-0a8e758f5e873d1c1"]
    eu-west-2      = ["ami-0194c3e07668a7e36","ami-0194c3e07668a7e36"]
    eu-west-3      = ["ami-0f7cd40eac2214b37","ami-0f7cd40eac2214b37"]
    eu-north-1     = ["ami-0ff338189efb7ed37","ami-0ff338189efb7ed37"]
    sa-east-1      = ["ami-054a31f1b3bf90920","ami-054a31f1b3bf90920"]
  }
}

variable "lookup-region_abbr" {
  description = "AWS Region: Abbreviation Lookup"
  type = map
  default = {
    ap-east-1      = "ape1"
    ap-northeast-1 = "apne1"
    ap-northeast-2 = "apne2"
    ap-northeast-3 = "apne3"
    ap-south-1     = "aps1"
    ap-southeast-1 = "apse1"
    ap-southeast-2 = "apse2"
    ca-central-1   = "cac1"
    eu-central-1   = "euc1"
    eu-north-1     = "eun1"
    eu-west-1      = "euw1"
    eu-west-2      = "euw2"
    eu-west-3      = "euw3"
    me-south-1     = "mes1"
    sa-east-1      = "sae1"
    us-east-1      = "use1"
    us-east-2      = "use2"
    us-west-1      = "usw1"
    us-west-2      = "usw2"
    us-gov-east-1  = "uge1"
    us-gov-west-1	 = "ugw1"
  }
}
# data "template_file" "user_data" {
#   template = file("deployagent.sh")
# }