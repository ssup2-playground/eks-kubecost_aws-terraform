# Provider
provider "aws" {
  region = local.region
}

provider "aws" {
  alias  = "ecr"
  region = "us-east-1"
}

provider "helm" {
  alias = "self"

  # to avoid issue : https://github.com/hashicorp/terraform-provider-helm/issues/630#issuecomment-996682323
  repository_config_path = "${path.module}/.helm/repositories.yaml" 
  repository_cache       = "${path.module}/.helm"

  kubernetes {
    host                   = module.eks_self.cluster_endpoint
    cluster_ca_certificate = base64decode(module.eks_self.cluster_certificate_authority_data)

    exec {
      api_version = "client.authentication.k8s.io/v1beta1"
      command     = "aws"
      args        = ["eks", "get-token", "--cluster-name", module.eks_self.cluster_name]
    }
  }
}

provider "helm" {
  alias = "self-amp"

  # to avoid issue : https://github.com/hashicorp/terraform-provider-helm/issues/630#issuecomment-996682323
  repository_config_path = "${path.module}/.helm/repositories.yaml" 
  repository_cache       = "${path.module}/.helm"

  kubernetes {
    host                   = module.eks_self_amp.cluster_endpoint
    cluster_ca_certificate = base64decode(module.eks_self_amp.cluster_certificate_authority_data)

    exec {
      api_version = "client.authentication.k8s.io/v1beta1"
      command     = "aws"
      args        = ["eks", "get-token", "--cluster-name", module.eks_self_amp.cluster_name]
    }
  }
}

provider "helm" {
  alias = "amp"

  # to avoid issue : https://github.com/hashicorp/terraform-provider-helm/issues/630#issuecomment-996682323
  repository_config_path = "${path.module}/.helm/repositories.yaml" 
  repository_cache       = "${path.module}/.helm"

  kubernetes {
    host                   = module.eks_amp.cluster_endpoint
    cluster_ca_certificate = base64decode(module.eks_amp.cluster_certificate_authority_data)

    exec {
      api_version = "client.authentication.k8s.io/v1beta1"
      command     = "aws"
      args        = ["eks", "get-token", "--cluster-name", module.eks_amp.cluster_name]
    }
  }
}

## Data
data "aws_availability_zones" "available" {}

data "aws_caller_identity" "current" {}

data "aws_ecrpublic_authorization_token" "token" {
  provider = aws.ecr
}

## AMP
module "prometheus_self_amp" {
  source = "terraform-aws-modules/managed-service-prometheus/aws"

  workspace_alias = format("%s-self-amp", local.name)
}

module "prometheus_amp" {
  source = "terraform-aws-modules/managed-service-prometheus/aws"

  workspace_alias = format("%s-amp", local.name)
}

## VPC
module "vpc" {
  source = "terraform-aws-modules/vpc/aws"

  name = format("%s-vpc", local.name)

  cidr             = local.vpc_cidr
  azs              = local.azs
  public_subnets   = [for k, v in local.azs : cidrsubnet(local.vpc_cidr, 4, k)]
  private_subnets  = [for k, v in local.azs : cidrsubnet(local.vpc_cidr, 4, k + 4)]

  enable_nat_gateway   = true
  enable_dns_hostnames = true
  enable_dns_support   = true

  manage_default_network_acl    = true
  manage_default_route_table    = true
  manage_default_security_group = true

  public_subnet_tags = {
    "kubernetes.io/role/elb" = 1 # for AWS Load Balancer Controller
  }

  private_subnet_tags = {
    "kubernetes.io/role/internal-elb" = 1 # for AWS Load Balancer Controller
  }
}

## EKS Self
module "eks_self" {
  source = "terraform-aws-modules/eks/aws"

  cluster_name = format("%s-eks-self", local.name)
  cluster_version = "1.28"

  vpc_id                          = module.vpc.vpc_id
  subnet_ids                      = module.vpc.private_subnets
  cluster_endpoint_public_access  = true

  enable_cluster_creator_admin_permissions = true

  ## Managed Nodegroups
  eks_managed_node_groups = {
    default = {
      min_size     = 3
      max_size     = 3
      desired_size = 3

      instance_types = ["m5.xlarge"]
      iam_role_additional_policies = {
        AmazonSSMManagedInstanceCore = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
      }
    }
  }

  ## Addons
  cluster_addons = {
    coredns = {
      addon_version = "v1.10.1-eksbuild.5"
    }
    vpc-cni = {
      addon_version = "v1.14.1-eksbuild.1"
    }
    kube-proxy = {
      addon_version = "v1.28.1-eksbuild.1"
    }
    aws-ebs-csi-driver = {
      addon_version = "v1.25.0-eksbuild.1"
      service_account_role_arn = module.irsa_self_ebs_csi_plugin.iam_role_arn
    }
  }

  ## Node Security Group
  node_security_group_additional_rules = {
    ingress_self_all = {
      description = "Node to node all ports/protocols"
      protocol    = "-1"
      from_port   = 0
      to_port     = 0
      type        = "ingress"
      self        = true
    }
  }
}

module "irsa_self_ebs_csi_plugin" {
  source = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"

  role_name             = format("%s-irsa-self-ebs-csi-plugin", local.name)
  attach_ebs_csi_policy = true

  oidc_providers = {
    main = {
      provider_arn               = module.eks_self.oidc_provider_arn
      namespace_service_accounts = ["kube-system:ebs-csi-controller-sa", "kube-system:ebs-csi-node-sa"]
    }
  }
}

## EKS Self / Load Balancer Controller
module "irsa_self_load_balancer_controller" {
  source = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"

  role_name                              = format("%s-irsa-self-aws-load-balancer-controller", local.name)
  attach_load_balancer_controller_policy = true

  oidc_providers = {
    main = {
      provider_arn               = module.eks_self.oidc_provider_arn
      namespace_service_accounts = ["kube-system:aws-load-balancer-controller"]
    }
  }
}

resource "helm_release" "self_aws_load_balancer_controller" {
  provider = helm.self

  namespace  = "kube-system"
  name       = "aws-load-balancer-controller"
  chart      = "aws-load-balancer-controller"
  repository = "https://aws.github.io/eks-charts"
  version    = "v1.6.2"

  set {
    name  = "clusterName"
    value = module.eks_self.cluster_name
  }
  set {
    name  = "serviceAccount.annotations.eks\\.amazonaws\\.com/role-arn"
    value = module.irsa_self_load_balancer_controller.iam_role_arn
  }

  depends_on = [
    module.irsa_self_load_balancer_controller,
  ]
}

## EKS Self / Kubecost 
resource "helm_release" "kubecost_self" {
  provider = helm.self

  namespace        = "kubecost"
  create_namespace = true

  name       = "cost-analyzer"
  chart      = "cost-analyzer"
  repository = "https://kubecost.github.io/cost-analyzer"
  version    = "1.108.0"
 
  values = [
    file("${path.module}/helm-values/kubecost-self.yaml")
  ]

  set {
    name  = "clusterName"
    value = module.eks_self.cluster_name
  }
}

## EKS Self AMP
module "eks_self_amp" {
  source = "terraform-aws-modules/eks/aws"

  cluster_name = format("%s-eks-self-amp", local.name)
  cluster_version = "1.28"

  vpc_id                          = module.vpc.vpc_id
  subnet_ids                      = module.vpc.private_subnets
  cluster_endpoint_public_access  = true

  enable_cluster_creator_admin_permissions = true

  ## Managed Nodegroups
  eks_managed_node_groups = {
    default = {
      min_size     = 3
      max_size     = 3
      desired_size = 3

      instance_types = ["m5.xlarge"]
      iam_role_additional_policies = {
        AmazonSSMManagedInstanceCore = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
      }
    }
  }

  ## Addons
  cluster_addons = {
    coredns = {
      addon_version = "v1.10.1-eksbuild.5"
    }
    vpc-cni = {
      addon_version = "v1.14.1-eksbuild.1"
    }
    kube-proxy = {
      addon_version = "v1.28.1-eksbuild.1"
    }
    aws-ebs-csi-driver = {
      addon_version = "v1.25.0-eksbuild.1"
      service_account_role_arn = module.irsa_self_amp_ebs_csi_plugin.iam_role_arn
    }
  }

  ## Node Security Group
  node_security_group_additional_rules = {
    ingress_self_all = {
      description = "Node to node all ports/protocols"
      protocol    = "-1"
      from_port   = 0
      to_port     = 0
      type        = "ingress"
      self        = true
    }
  }
}

module "irsa_self_amp_ebs_csi_plugin" {
  source = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"

  role_name             = format("%s-irsa-self-amp-ebs-csi-plugin", local.name)
  attach_ebs_csi_policy = true

  oidc_providers = {
    main = {
      provider_arn               = module.eks_self_amp.oidc_provider_arn
      namespace_service_accounts = ["kube-system:ebs-csi-controller-sa", "kube-system:ebs-csi-node-sa"]
    }
  }
}

## EKS Self AMP / Load Balancer Controller
module "irsa_self_amp_load_balancer_controller" {
  source = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"

  role_name                              = format("%s-irsa-self-amp-aws-load-balancer-controller", local.name)
  attach_load_balancer_controller_policy = true

  oidc_providers = {
    main = {
      provider_arn               = module.eks_self_amp.oidc_provider_arn
      namespace_service_accounts = ["kube-system:aws-load-balancer-controller"]
    }
  }
}

resource "helm_release" "self_amp_aws_load_balancer_controller" {
  provider = helm.self-amp

  namespace  = "kube-system"
  name       = "aws-load-balancer-controller"
  chart      = "aws-load-balancer-controller"
  repository = "https://aws.github.io/eks-charts"
  version    = "v1.6.2"

  set {
    name  = "clusterName"
    value = module.eks_self_amp.cluster_name
  }
  set {
    name  = "serviceAccount.annotations.eks\\.amazonaws\\.com/role-arn"
    value = module.irsa_self_amp_load_balancer_controller.iam_role_arn
  }

  depends_on = [
    module.irsa_self_amp_load_balancer_controller,
  ]
}

## EKS Self AMP / Kubecost
module "irsa_self_amp_kubecost" {
  source = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"

  role_name                                       = format("%s-self-amp-kubecost", local.name)
  attach_amazon_managed_service_prometheus_policy = true

  oidc_providers = {
    main = {
      provider_arn               = module.eks_self_amp.oidc_provider_arn
      namespace_service_accounts = ["kubecost:cost-analyzer"]
    }
  }
}


module "irsa_self_amp_prometheus" {
  source = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"

  role_name                                       = format("%s-self-amp-prometheus", local.name)
  attach_amazon_managed_service_prometheus_policy = true

  oidc_providers = {
    main = {
      provider_arn               = module.eks_self_amp.oidc_provider_arn
      namespace_service_accounts = ["kubecost:cost-analyzer-prometheus-server"]
    }
  }
}

resource "helm_release" "kubecost_self_amp" {
  provider = helm.self-amp

  namespace        = "kubecost"
  create_namespace = true

  name       = "cost-analyzer"
  chart      = "cost-analyzer"
  repository = "https://kubecost.github.io/cost-analyzer"
  version    = "1.108.0"
 
  values = [
    file("${path.module}/helm-values/kubecost-self-amp.yaml")
  ]

  set {
    name  = "clusterName"
    value = module.eks_self_amp.cluster_name
  }
  set {
    name  = "serviceAccount.annotations.eks\\.amazonaws\\.com/role-arn"
    value = module.irsa_self_amp_kubecost.iam_role_arn
  }
  set {
    name  = "prometheus.serviceAccounts.server.annotations.eks\\.amazonaws\\.com/role-arn"
    value = module.irsa_self_amp_prometheus.iam_role_arn
  }
  set {
    name  = "global.amp.prometheusServerEndpoint"
    value = format("http://localhost:8005/workspaces/%s/", module.prometheus_self_amp.workspace_id)
  }
  set {
    name  = "global.amp.remoteWriteService"
    value = format("%sapi/v1/remote_write", module.prometheus_self_amp.workspace_prometheus_endpoint)
  }
}

## EKS AMP
module "eks_amp" {
  source = "terraform-aws-modules/eks/aws"

  cluster_name = format("%s-eks-amp", local.name)
  cluster_version = "1.28"

  vpc_id                          = module.vpc.vpc_id
  subnet_ids                      = module.vpc.private_subnets
  cluster_endpoint_public_access  = true

  enable_cluster_creator_admin_permissions = true

  ## Managed Nodegroups
  eks_managed_node_groups = {
    default = {
      min_size     = 3
      max_size     = 3
      desired_size = 3

      instance_types = ["m5.xlarge"]
      iam_role_additional_policies = {
        AmazonSSMManagedInstanceCore = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
      }
    }
  }

  ## Addons
  cluster_addons = {
    coredns = {
      addon_version = "v1.10.1-eksbuild.5"
    }
    vpc-cni = {
      addon_version = "v1.14.1-eksbuild.1"
    }
    kube-proxy = {
      addon_version = "v1.28.1-eksbuild.1"
    }
    aws-ebs-csi-driver = {
      addon_version = "v1.25.0-eksbuild.1"
      service_account_role_arn = module.irsa_amp_ebs_csi_plugin.iam_role_arn
    }
  }

  ## Node Security Group
  node_security_group_additional_rules = {
    ingress_self_all = {
      description = "Node to node all ports/protocols"
      protocol    = "-1"
      from_port   = 0
      to_port     = 0
      type        = "ingress"
      self        = true
    }
  }
}

module "irsa_amp_ebs_csi_plugin" {
  source = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"

  role_name             = format("%s-irsa-amp-ebs-csi-plugin", local.name)
  attach_ebs_csi_policy = true

  oidc_providers = {
    main = {
      provider_arn               = module.eks_amp.oidc_provider_arn
      namespace_service_accounts = ["kube-system:ebs-csi-controller-sa", "kube-system:ebs-csi-node-sa"]
    }
  }
}

## EKS AMP / Load Balancer Controller
module "irsa_amp_load_balancer_controller" {
  source = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"

  role_name                              = format("%s-irsa-amp-aws-load-balancer-controller", local.name)
  attach_load_balancer_controller_policy = true

  oidc_providers = {
    main = {
      provider_arn               = module.eks_amp.oidc_provider_arn
      namespace_service_accounts = ["kube-system:aws-load-balancer-controller"]
    }
  }
}

resource "helm_release" "amp_aws_load_balancer_controller" {
  provider = helm.amp

  namespace  = "kube-system"
  name       = "aws-load-balancer-controller"
  chart      = "aws-load-balancer-controller"
  repository = "https://aws.github.io/eks-charts"
  version    = "v1.6.2"

  set {
    name  = "clusterName"
    value = module.eks_amp.cluster_name
  }
  set {
    name  = "serviceAccount.annotations.eks\\.amazonaws\\.com/role-arn"
    value = module.irsa_amp_load_balancer_controller.iam_role_arn
  }

  depends_on = [
    module.irsa_amp_load_balancer_controller,
  ]
}

## EKS AMP / Kubecost
resource "helm_release" "kubecost_amp" {
  provider = helm.amp

  namespace        = "kubecost"
  create_namespace = true

  name       = "cost-analyzer"
  chart      = "cost-analyzer"
  repository = "https://kubecost.github.io/cost-analyzer"
  version    = "1.108.0"
 
  values = [
    file("${path.module}/helm-values/kubecost-amp.yaml")
  ]

  set {
    name  = "clusterName"
    value = module.eks_amp.cluster_name
  }
}
