# Provider
provider "aws" {
  region = local.region
}

provider "aws" {
  alias  = "ecr"
  region = "us-east-1"
}

provider "kubernetes" {
  host                   = module.eks.cluster_endpoint
  cluster_ca_certificate = base64decode(module.eks.cluster_certificate_authority_data)

  exec {
    api_version = "client.authentication.k8s.io/v1beta1"
    command     = "aws"
    args        = ["eks", "get-token", "--cluster-name", module.eks.cluster_name]
  }
}

provider "helm" {
  # to avoid issue : https://github.com/hashicorp/terraform-provider-helm/issues/630#issuecomment-996682323
  repository_config_path = "${path.module}/.helm/repositories.yaml" 
  repository_cache       = "${path.module}/.helm"

  kubernetes {
    host                   = module.eks.cluster_endpoint
    cluster_ca_certificate = base64decode(module.eks.cluster_certificate_authority_data)

    exec {
      api_version = "client.authentication.k8s.io/v1beta1"
      command     = "aws"
      args        = ["eks", "get-token", "--cluster-name", module.eks.cluster_name]
    }
  }
}

provider "kubectl" {
  apply_retry_count      = 5
  host                   = module.eks.cluster_endpoint
  cluster_ca_certificate = base64decode(module.eks.cluster_certificate_authority_data)
  load_config_file       = false

  exec {
    api_version = "client.authentication.k8s.io/v1beta1"
    command     = "aws"
    args        = ["eks", "get-token", "--cluster-name", module.eks.cluster_name]
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
    "kubernetes.io/role/internal-elb" = 1                               # for AWS Load Balancer Controller
    "karpenter.sh/discovery"          = format("%s-eks", local.name) # for Karpenter
  }
}

## EKS 
module "eks" {
  source = "terraform-aws-modules/eks/aws"

  cluster_name = format("%s-eks", local.name)
  cluster_version = "1.28"

  vpc_id                          = module.vpc.vpc_id
  subnet_ids                      = module.vpc.private_subnets
  cluster_endpoint_public_access  = true

  enable_cluster_creator_admin_permissions = true

  ## Addons
  cluster_addons = {
    coredns = {
      addon_version = "v1.10.1-eksbuild.5"
      configuration_values = file("${path.module}/eks-addon-configs/coredns.json")
    }
    vpc-cni = {
      addon_version = "v1.14.1-eksbuild.1"
    }
    kube-proxy = {
      addon_version = "v1.28.1-eksbuild.1"
    }
    aws-ebs-csi-driver = {
      addon_version = "v1.25.0-eksbuild.1"
      service_account_role_arn = module.irsa_ebs_csi_plugin.iam_role_arn
      configuration_values = file("${path.module}/eks-addon-configs/ebs-csi.json")
    }
  }

  ## Fargate
  fargate_profiles = {
    karpenter = {
      selectors = [
        { namespace = "karpenter" }
      ]
    }
  }

  ## Node Security Group
  node_security_group_tags = {
    "karpenter.sh/discovery" = format("%s-eks", local.name) # for Karpenter
  }
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

module "irsa_ebs_csi_plugin" {
  source = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"

  role_name             = format("%s-irsa-ebs-csi-plugin", local.name)
  attach_ebs_csi_policy = true

  oidc_providers = {
    main = {
      provider_arn               = module.eks.oidc_provider_arn
      namespace_service_accounts = ["kube-system:ebs-csi-controller-sa", "kube-system:ebs-csi-node-sa"]
    }
  }
}

## EKS / Karpenter
module "karpenter" {
  source = "terraform-aws-modules/eks/aws//modules/karpenter"

  cluster_name           = module.eks.cluster_name
  irsa_oidc_provider_arn = module.eks.oidc_provider_arn

  create_instance_profile = false
  enable_irsa             = true

  node_iam_role_additional_policies = {
    AmazonSSMManagedInstanceCore = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
  }
}

resource "helm_release" "karpenter" {
  namespace        = "karpenter"
  create_namespace = true

  name       = "karpenter"
  chart      = "karpenter"
  repository = "oci://public.ecr.aws/karpenter"
  version    = "v0.32.5"

  set {
    name  = "settings.aws.clusterName"
    value = module.eks.cluster_name
  }
  set {
    name  = "settings.aws.clusterEndpoint"
    value = module.eks.cluster_endpoint
  }
  set {
    name  = "settings.aws.interruptionQueueName"
    value = module.karpenter.queue_name
  }
  set {
    name  = "serviceAccount.annotations.eks\\.amazonaws\\.com/role-arn"
    value = module.karpenter.iam_role_arn
  }

  depends_on = [
    module.karpenter
  ]
}

resource "kubectl_manifest" "karpenter_nodepool_core" {
  yaml_body = file("${path.module}/manifests/karpenter-nodepool-core.yaml")

  depends_on = [
    helm_release.karpenter
  ]
}

resource "kubectl_manifest" "karpenter_nodepool_default" {
  yaml_body = file("${path.module}/manifests/karpenter-nodepool-default.yaml")

  depends_on = [
    helm_release.karpenter
  ]
}

resource "kubectl_manifest" "karpenter_ec2nodeclass_default" {
  yaml_body = templatefile("${path.module}/manifests/karpenter-nodeclass-default.yaml", 
    { 
      cluster_name = module.eks.cluster_name
      ec2_role_name = module.karpenter.node_iam_role_name
    }
  )

  depends_on = [
    helm_release.karpenter
  ]
}

## EKS / Load Balancer Controller
module "irsa_load_balancer_controller" {
  source = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"

  role_name                              = format("%s-irsa-aws-load-balancer-controller", local.name)
  attach_load_balancer_controller_policy = true

  oidc_providers = {
    main = {
      provider_arn               = module.eks.oidc_provider_arn
      namespace_service_accounts = ["kube-system:aws-load-balancer-controller"]
    }
  }
}

resource "helm_release" "aws_load_balancer_controller" {
  namespace  = "kube-system"
  name       = "aws-load-balancer-controller"
  chart      = "aws-load-balancer-controller"
  repository = "https://aws.github.io/eks-charts"
  version    = "v1.6.2"
 
  values = [
    file("${path.module}/helm-values/aws-load-balancer-controller.yaml")
  ]

  set {
    name  = "clusterName"
    value = module.eks.cluster_name
  }
  set {
    name  = "serviceAccount.name"
    value = "aws-load-balancer-controller"
  }
  set {
    name  = "serviceAccount.annotations.eks\\.amazonaws\\.com/role-arn"
    value = module.irsa_load_balancer_controller.iam_role_arn
  }

  depends_on = [
    module.irsa_load_balancer_controller,
		helm_release.karpenter
  ]
}

## EKS / Kubecost Self
resource "helm_release" "kubecost-self" {
  namespace        = "kubecost-self"
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
    value = module.eks.cluster_name
  }

  depends_on = [
		helm_release.karpenter
  ]
}

## EKS / Kubecost Self AMP
module "irsa_self_amp_kubecost" {
  source = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"

  role_name                                       = format("%s-self-amp-kubecost", local.name)
  attach_amazon_managed_service_prometheus_policy = true

  oidc_providers = {
    main = {
      provider_arn               = module.eks.oidc_provider_arn
      namespace_service_accounts = ["kubecost-self-amp:cost-analyzer"]
    }
  }
}

module "irsa_self_amp_prometheus" {
  source = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"

  role_name                                       = format("%s-self-amp-prometheus", local.name)
  attach_amazon_managed_service_prometheus_policy = true

  oidc_providers = {
    main = {
      provider_arn               = module.eks.oidc_provider_arn
      namespace_service_accounts = ["kubecost-self-amp:cost-analyzer-prometheus-server"]
    }
  }
}

resource "helm_release" "kubecost-self-amp" {
  namespace        = "kubecost-self-amp"
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
    value = module.eks.cluster_name
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
    value = module.prometheus_self_amp.workspace_prometheus_endpoint
  }

  depends_on = [
		helm_release.karpenter
  ]
}

## EKS / Kubecost AMP
resource "helm_release" "kubecost-amp" {
  namespace        = "kubecost-amp"
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
    value = module.eks.cluster_name
  }

  depends_on = [
		helm_release.karpenter
  ]
}
