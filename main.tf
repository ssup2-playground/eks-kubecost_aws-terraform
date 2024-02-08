provider "aws" {
  region = local.region
}

provider "aws" {
  alias  = "ecr"
  region = "us-east-1"
}

provider "kubernetes" {
  alias = "amp"

  host                   = module.eks_amp.cluster_endpoint
  cluster_ca_certificate = base64decode(module.eks_amp.cluster_certificate_authority_data)

  exec {
    api_version = "client.authentication.k8s.io/v1beta1"
    command     = "aws"
    args        = ["eks", "get-token", "--cluster-name", module.eks_amp.cluster_name]
  }
}

provider "helm" {
  alias = "prom"

  # to avoid issue : https://github.com/hashicorp/terraform-provider-helm/issues/630#issuecomment-996682323
  repository_config_path = "${path.module}/.helm/repositories.yaml" 
  repository_cache       = "${path.module}/.helm"

  kubernetes {
    host                   = module.eks_prom.cluster_endpoint
    cluster_ca_certificate = base64decode(module.eks_prom.cluster_certificate_authority_data)

    exec {
      api_version = "client.authentication.k8s.io/v1beta1"
      command     = "aws"
      args        = ["eks", "get-token", "--cluster-name", module.eks_prom.cluster_name]
    }
  }
}

provider "helm" {
  alias = "adot-amp"

  # to avoid issue : https://github.com/hashicorp/terraform-provider-helm/issues/630#issuecomment-996682323
  repository_config_path = "${path.module}/.helm/repositories.yaml" 
  repository_cache       = "${path.module}/.helm"

  kubernetes {
    host                   = module.eks_adot_amp.cluster_endpoint
    cluster_ca_certificate = base64decode(module.eks_adot_amp.cluster_certificate_authority_data)

    exec {
      api_version = "client.authentication.k8s.io/v1beta1"
      command     = "aws"
      args        = ["eks", "get-token", "--cluster-name", module.eks_adot_amp.cluster_name]
    }
  }
}

provider "helm" {
  alias = "prom-amp"

  # to avoid issue : https://github.com/hashicorp/terraform-provider-helm/issues/630#issuecomment-996682323
  repository_config_path = "${path.module}/.helm/repositories.yaml" 
  repository_cache       = "${path.module}/.helm"

  kubernetes {
    host                   = module.eks_prom_amp.cluster_endpoint
    cluster_ca_certificate = base64decode(module.eks_prom_amp.cluster_certificate_authority_data)

    exec {
      api_version = "client.authentication.k8s.io/v1beta1"
      command     = "aws"
      args        = ["eks", "get-token", "--cluster-name", module.eks_prom_amp.cluster_name]
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

provider "kubectl" {
  alias = "adot-amp"

  apply_retry_count      = 5
  host                   = module.eks_adot_amp.cluster_endpoint
  cluster_ca_certificate = base64decode(module.eks_adot_amp.cluster_certificate_authority_data)
  load_config_file       = false

  exec {
    api_version = "client.authentication.k8s.io/v1beta1"
    command     = "aws"
    args        = ["eks", "get-token", "--cluster-name", module.eks_adot_amp.cluster_name]
  }
}

provider "kubectl" {
  alias = "amp"

  apply_retry_count      = 5
  host                   = module.eks_amp.cluster_endpoint
  cluster_ca_certificate = base64decode(module.eks_amp.cluster_certificate_authority_data)
  load_config_file       = false

  exec {
    api_version = "client.authentication.k8s.io/v1beta1"
    command     = "aws"
    args        = ["eks", "get-token", "--cluster-name", module.eks_amp.cluster_name]
  }
}

## Data
data "aws_availability_zones" "available" {}

data "aws_caller_identity" "current" {}

data "aws_ecrpublic_authorization_token" "token" {
  provider = aws.ecr
}

## AMP
module "prometheus_prom_amp" {
  source = "terraform-aws-modules/managed-service-prometheus/aws"

  workspace_alias = format("%s-prom-amp", local.name)
}

module "prometheus_adot_amp" {
  source = "terraform-aws-modules/managed-service-prometheus/aws"

  workspace_alias = format("%s-adot-amp", local.name)
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

## EKS Prom
module "eks_prom" {
  source = "terraform-aws-modules/eks/aws"

  cluster_name = format("%s-prom-eks", local.name)
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
      service_account_role_arn = module.irsa_prom_ebs_csi_plugin.iam_role_arn
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

module "irsa_prom_ebs_csi_plugin" {
  source = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"

  role_name             = format("%s-irsa-prom-ebs-csi-plugin", local.name)
  attach_ebs_csi_policy = true

  oidc_providers = {
    main = {
      provider_arn               = module.eks_prom.oidc_provider_arn
      namespace_service_accounts = ["kube-system:ebs-csi-controller-sa", "kube-system:ebs-csi-node-sa"]
    }
  }
}

## EKS Prom / Load Balancer Controller
module "irsa_prom_load_balancer_controller" {
  source = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"

  role_name                              = format("%s-irsa-prom-aws-load-balancer-controller", local.name)
  attach_load_balancer_controller_policy = true

  oidc_providers = {
    main = {
      provider_arn               = module.eks_prom.oidc_provider_arn
      namespace_service_accounts = ["kube-system:aws-load-balancer-controller"]
    }
  }
}

resource "helm_release" "prom_aws_load_balancer_controller" {
  provider = helm.prom

  namespace  = "kube-system"
  name       = "aws-load-balancer-controller"
  chart      = "aws-load-balancer-controller"
  repository = "https://aws.github.io/eks-charts"
  version    = "v1.6.2"

  set {
    name  = "clusterName"
    value = module.eks_prom.cluster_name
  }
  set {
    name  = "serviceAccount.annotations.eks\\.amazonaws\\.com/role-arn"
    value = module.irsa_prom_load_balancer_controller.iam_role_arn
  }

  depends_on = [
    module.irsa_prom_load_balancer_controller,
  ]
}

## EKS Prom / Kubecost 
resource "helm_release" "prom_kubecost" {
  provider = helm.prom

  namespace        = "kubecost"
  create_namespace = true

  name       = "cost-analyzer"
  chart      = "cost-analyzer"
  repository = "https://kubecost.github.io/cost-analyzer"
  version    = "1.108.0"
 
  values = [
    file("${path.module}/helm-values/kubecost-prom.yaml")
  ]

  set {
    name  = "clusterName"
    value = module.eks_prom.cluster_name
  }
}

## EKS Prom AMP
module "eks_prom_amp" {
  source = "terraform-aws-modules/eks/aws"

  cluster_name = format("%s-prom-amp-eks", local.name)
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
      service_account_role_arn = module.irsa_prom_amp_ebs_csi_plugin.iam_role_arn
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

module "irsa_prom_amp_ebs_csi_plugin" {
  source = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"

  role_name             = format("%s-irsa-prom-amp-ebs-csi-plugin", local.name)
  attach_ebs_csi_policy = true

  oidc_providers = {
    main = {
      provider_arn               = module.eks_prom_amp.oidc_provider_arn
      namespace_service_accounts = ["kube-system:ebs-csi-controller-sa", "kube-system:ebs-csi-node-sa"]
    }
  }
}

## EKS Prom AMP / Load Balancer Controller
module "irsa_prom_amp_load_balancer_controller" {
  source = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"

  role_name                              = format("%s-irsa-prom-amp-aws-load-balancer-controller", local.name)
  attach_load_balancer_controller_policy = true

  oidc_providers = {
    main = {
      provider_arn               = module.eks_prom_amp.oidc_provider_arn
      namespace_service_accounts = ["kube-system:aws-load-balancer-controller"]
    }
  }
}

resource "helm_release" "prom_amp_aws_load_balancer_controller" {
  provider = helm.prom-amp

  namespace  = "kube-system"
  name       = "aws-load-balancer-controller"
  chart      = "aws-load-balancer-controller"
  repository = "https://aws.github.io/eks-charts"
  version    = "v1.6.2"

  set {
    name  = "clusterName"
    value = module.eks_prom_amp.cluster_name
  }
  set {
    name  = "serviceAccount.annotations.eks\\.amazonaws\\.com/role-arn"
    value = module.irsa_prom_amp_load_balancer_controller.iam_role_arn
  }

  depends_on = [
    module.irsa_prom_amp_load_balancer_controller,
  ]
}

## EKS Prom AMP / Kubecost
module "irsa_prom_amp_kubecost" {
  source = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"

  role_name                                       = format("%s-prom-amp-kubecost", local.name)
  attach_amazon_managed_service_prometheus_policy = true

  oidc_providers = {
    main = {
      provider_arn               = module.eks_prom_amp.oidc_provider_arn
      namespace_service_accounts = ["kubecost:cost-analyzer"]
    }
  }
}


module "irsa_prom_amp_prometheus" {
  source = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"

  role_name                                       = format("%s-prom-amp-prometheus", local.name)
  attach_amazon_managed_service_prometheus_policy = true

  oidc_providers = {
    main = {
      provider_arn               = module.eks_prom_amp.oidc_provider_arn
      namespace_service_accounts = ["kubecost:cost-analyzer-prometheus-server"]
    }
  }
}

resource "helm_release" "prom_amp_kubecost" {
  provider = helm.prom-amp

  namespace        = "kubecost"
  create_namespace = true

  name       = "cost-analyzer"
  chart      = "cost-analyzer"
  repository = "https://kubecost.github.io/cost-analyzer"
  version    = "1.108.0"
 
  values = [
    file("${path.module}/helm-values/kubecost-prom-amp.yaml")
  ]

  set {
    name  = "clusterName"
    value = module.eks_prom_amp.cluster_name
  }
  set {
    name  = "serviceAccount.annotations.eks\\.amazonaws\\.com/role-arn"
    value = module.irsa_prom_amp_kubecost.iam_role_arn
  }
  set {
    name  = "prometheus.serviceAccounts.server.annotations.eks\\.amazonaws\\.com/role-arn"
    value = module.irsa_prom_amp_prometheus.iam_role_arn
  }
  set {
    name  = "global.amp.prometheusServerEndpoint"
    value = format("http://localhost:8005/workspaces/%s/", module.prometheus_prom_amp.workspace_id)
  }
  set {
    name  = "global.amp.remoteWriteService"
    value = format("%sapi/v1/remote_write", module.prometheus_prom_amp.workspace_prometheus_endpoint)
  }
}

## EKS ADOT AMP
module "eks_adot_amp" {
  source = "terraform-aws-modules/eks/aws"

  cluster_name = format("%s-adot-amp-eks", local.name)
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
      service_account_role_arn = module.irsa_adot_amp_ebs_csi_plugin.iam_role_arn
    }
    adot = {
      addon_version = "v0.90.0-eksbuild.1"
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

module "irsa_adot_amp_ebs_csi_plugin" {
  source = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"

  role_name             = format("%s-irsa-adot-amp-ebs-csi-plugin", local.name)
  attach_ebs_csi_policy = true

  oidc_providers = {
    main = {
      provider_arn               = module.eks_adot_amp.oidc_provider_arn
      namespace_service_accounts = ["kube-system:ebs-csi-controller-sa", "kube-system:ebs-csi-node-sa"]
    }
  }
}

## EKS ADOT AMP / Cert Manager
resource "helm_release" "adot_amp_cert_manager" {
  provider = helm.adot-amp

  create_namespace = true
  namespace  = "cert-manager"

  name       = "cert-manager"
  chart      = "cert-manager"
  repository = "https://charts.jetstack.io"
  version    = "v1.13.3"

  values = [
    file("${path.module}/helm-values/cert-manager.yaml")
  ]
  set {
    name  = "clusterName"
    value = module.eks_adot_amp.cluster_name
  }
}

## EKS ADOT AMP / Load Balancer Controller
module "irsa_adot_amp_load_balancer_controller" {
  source = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"

  role_name                              = format("%s-irsa-adot-amp-aws-load-balancer-controller", local.name)
  attach_load_balancer_controller_policy = true

  oidc_providers = {
    main = {
      provider_arn               = module.eks_adot_amp.oidc_provider_arn
      namespace_service_accounts = ["kube-system:aws-load-balancer-controller"]
    }
  }
}

resource "helm_release" "adot_amp_aws_load_balancer_controller" {
  provider = helm.adot-amp

  namespace  = "kube-system"
  name       = "aws-load-balancer-controller"
  chart      = "aws-load-balancer-controller"
  repository = "https://aws.github.io/eks-charts"
  version    = "v1.6.2"

  set {
    name  = "clusterName"
    value = module.eks_adot_amp.cluster_name
  }
  set {
    name  = "serviceAccount.annotations.eks\\.amazonaws\\.com/role-arn"
    value = module.irsa_adot_amp_load_balancer_controller.iam_role_arn
  }

  depends_on = [
    module.irsa_adot_amp_load_balancer_controller,
  ]
}

## EKS ADOT AMP / Kubecost
module "irsa_adot_amp_kubecost" {
  source = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"

  role_name                                       = format("%s-adot-amp-kubecost", local.name)
  attach_amazon_managed_service_prometheus_policy = true

  oidc_providers = {
    main = {
      provider_arn               = module.eks_adot_amp.oidc_provider_arn
      namespace_service_accounts = ["kubecost:cost-analyzer"]
    }
  }
}


module "irsa_adot_amp_prometheus" {
  source = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"

  role_name                                       = format("%s-adot-amp-prometheus", local.name)
  attach_amazon_managed_service_prometheus_policy = true

  oidc_providers = {
    main = {
      provider_arn               = module.eks_adot_amp.oidc_provider_arn
      namespace_service_accounts = ["kubecost:cost-analyzer-prometheus-server"]
    }
  }
}

resource "helm_release" "adot_amp_kubecost" {
  provider = helm.adot-amp

  namespace        = "kubecost"
  create_namespace = true

  name       = "cost-analyzer"
  chart      = "cost-analyzer"
  repository = "https://kubecost.github.io/cost-analyzer"
  version    = "1.108.0"
 
  values = [
    file("${path.module}/helm-values/kubecost-adot-amp.yaml")
  ]

  set {
    name  = "clusterName"
    value = module.eks_adot_amp.cluster_name
  }
  set {
    name  = "serviceAccount.annotations.eks\\.amazonaws\\.com/role-arn"
    value = module.irsa_adot_amp_kubecost.iam_role_arn
  }
  set {
    name  = "prometheus.serviceAccounts.server.annotations.eks\\.amazonaws\\.com/role-arn"
    value = module.irsa_adot_amp_prometheus.iam_role_arn
  }
  set {
    name  = "global.amp.prometheusServerEndpoint"
    value = format("http://localhost:8005/workspaces/%s/", module.prometheus_adot_amp.workspace_id)
  }
}

module "irsa_adot_amp_adot_collector_amp" {
  source = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"

  role_name                                       = format("%s-irsa-adot-amp-adot-collector-amp", local.name)
  attach_amazon_managed_service_prometheus_policy = true

  oidc_providers = {
    main = {
      provider_arn               = module.eks_adot_amp.oidc_provider_arn
      namespace_service_accounts = ["kubecost:adot-collector-amp"]
    }
  }
}

#data "kubectl_file_documents" "adot_amp_adot_amp" {
#  content = templatefile("${path.module}/manifests/adot-amp.yaml",
#    {
#      region                    = local.region
#      amp_role_arn              = module.irsa_adot_amp_adot_collector_amp.iam_role_arn
#      amp_remote_write_endpoint = format("https://aps-workspaces.%s.amazonaws.com/workspaces/%s/api/v1/remote_write", local.region, module.prometheus_adot_amp.workspace_id)
#    }
#  )
#}

#resource "kubectl_manifest" "adot_amp_adot_amp" {
#  provider = kubectl.adot-amp

#  for_each = data.kubectl_file_documents.adot_amp_adot_amp.manifests
#  yaml_body = each.value
#}

## EKS AMP
module "eks_amp" {
  source = "terraform-aws-modules/eks/aws"

  cluster_name = format("%s-amp-eks", local.name)
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

module "eks-aws-auth" {
  providers = {
    kubernetes = kubernetes.amp
  }

  source  = "terraform-aws-modules/eks/aws//modules/aws-auth"

  aws_auth_roles = [
    {
      rolearn  = format("arn:aws:iam::%s:role/AWSServiceRoleForAmazonPrometheusScraper_%s", data.aws_caller_identity.current.account_id, substr(aws_prometheus_scraper.amp_scraper.role_arn, -15, -1))
      username = "aps-collector-user"
    }
  ]
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
module "irsa_amp_kubecost" {
  source = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"

  role_name                                       = format("%s-amp-kubecost", local.name)
  attach_amazon_managed_service_prometheus_policy = true

  oidc_providers = {
    main = {
      provider_arn               = module.eks_amp.oidc_provider_arn
      namespace_service_accounts = ["kubecost:cost-analyzer"]
    }
  }
}

module "irsa_amp_prometheus" {
  source = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"

  role_name                                       = format("%s-amp-prometheus", local.name)
  attach_amazon_managed_service_prometheus_policy = true

  oidc_providers = {
    main = {
      provider_arn               = module.eks_amp.oidc_provider_arn
      namespace_service_accounts = ["kubecost:cost-analyzer-prometheus-server"]
    }
  }
}

resource "helm_release" "amp_kubecost" {
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
  set {
    name  = "serviceAccount.annotations.eks\\.amazonaws\\.com/role-arn"
    value = module.irsa_amp_kubecost.iam_role_arn
  }
  set {
    name  = "prometheus.serviceAccounts.server.annotations.eks\\.amazonaws\\.com/role-arn"
    value = module.irsa_amp_prometheus.iam_role_arn
  }
  set {
    name  = "global.amp.prometheusServerEndpoint"
    value = format("http://localhost:8005/workspaces/%s/", module.prometheus_amp.workspace_id)
  }
}

resource "aws_prometheus_scraper" "amp_scraper" {
  source {
    eks {
      cluster_arn = module.eks_amp.cluster_arn
      subnet_ids  = module.vpc.private_subnets
    }
  }

  destination {
    amp {
      workspace_arn = module.prometheus_amp.workspace_arn
    }
  }

  scrape_configuration = <<EOT
global:
  scrape_interval: 30s
scrape_configs:
  - job_name: pod_exporter
    kubernetes_sd_configs:
      - role: pod
  - job_name: cadvisor
    scheme: https
    authorization:
      credentials_file: /var/run/secrets/kubernetes.io/serviceaccount/token
    kubernetes_sd_configs:
      - role: node
    relabel_configs:
      - action: labelmap
        regex: __meta_kubernetes_node_label_(.+)
      - replacement: kubernetes.default.svc:443
        target_label: __address__
      - source_labels: [__meta_kubernetes_node_name]
        regex: (.+)
        target_label: __metrics_path__
        replacement: /api/v1/nodes/$1/proxy/metrics/cadvisor
  # apiserver metrics
  - scheme: https
    authorization:
      credentials_file: /var/run/secrets/kubernetes.io/serviceaccount/token
    job_name: kubernetes-apiservers
    kubernetes_sd_configs:
    - role: endpoints
    relabel_configs:
    - action: keep
      regex: default;kubernetes;https
      source_labels:
      - __meta_kubernetes_namespace
      - __meta_kubernetes_service_name
      - __meta_kubernetes_endpoint_port_name
  # kube proxy metrics
  - job_name: kube-proxy
    honor_labels: true
    kubernetes_sd_configs:
    - role: pod
    relabel_configs:
    - action: keep
      source_labels:
      - __meta_kubernetes_namespace
      - __meta_kubernetes_pod_name
      separator: '/'
      regex: 'kube-system/kube-proxy.+'
    - source_labels:
      - __address__
      action: replace
      target_label: __address__
      regex: (.+?)(\\:\\d+)?
      replacement: $1:10249
EOT
}

resource "kubectl_manifest" "amp_amp_scrapper_role" {
  provider = kubectl.amp

  yaml_body = file("${path.module}/manifests/amp-scrapper-role.yaml")
}

