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
  alias = "promcost"

  # to avoid issue : https://github.com/hashicorp/terraform-provider-helm/issues/630#issuecomment-996682323
  repository_config_path = "${path.module}/.helm/repositories.yaml" 
  repository_cache       = "${path.module}/.helm"

  kubernetes {
    host                   = module.eks_prom_ampcost.cluster_endpoint
    cluster_ca_certificate = base64decode(module.eks_prom_ampcost.cluster_certificate_authority_data)

    exec {
      api_version = "client.authentication.k8s.io/v1beta1"
      command     = "aws"
      args        = ["eks", "get-token", "--cluster-name", module.eks_prom_ampcost.cluster_name]
    }
  }
}

provider "helm" {
  alias = "prom-ampcost"

  # to avoid issue : https://github.com/hashicorp/terraform-provider-helm/issues/630#issuecomment-996682323
  repository_config_path = "${path.module}/.helm/repositories.yaml" 
  repository_cache       = "${path.module}/.helm"

  kubernetes {
    host                   = module.eks_prom_ampcost.cluster_endpoint
    cluster_ca_certificate = base64decode(module.eks_prom_ampcost.cluster_certificate_authority_data)

    exec {
      api_version = "client.authentication.k8s.io/v1beta1"
      command     = "aws"
      args        = ["eks", "get-token", "--cluster-name", module.eks_prom_ampcost.cluster_name]
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

module "prometheus_prom_ampcost" {
  source = "terraform-aws-modules/managed-service-prometheus/aws"

  workspace_alias = format("%s-prom-ampcost", local.name)
}

module "prometheus_adot_amp" {
  source = "terraform-aws-modules/managed-service-prometheus/aws"

  workspace_alias = format("%s-adot-amp", local.name)

  rule_group_namespaces = {
    CPU = {
      name = "CPU"
      data = <<-EOT
      groups:
      - name: CPU
        rules:
        - expr: sum(rate(container_cpu_usage_seconds_total{container!=""}[5m]))
          record: cluster:cpu_usage:rate5m
        - expr: rate(container_cpu_usage_seconds_total{container!=""}[5m])
          record: cluster:cpu_usage_nosum:rate5m
        - expr: avg(irate(container_cpu_usage_seconds_total{container!="POD", container!=""}[5m])) by (container,pod,namespace)
          record: kubecost_container_cpu_usage_irate
        - expr: sum(container_memory_working_set_bytes{container!="POD",container!=""}) by (container,pod,namespace)
          record: kubecost_container_memory_working_set_bytes
        - expr: sum(container_memory_working_set_bytes{container!="POD",container!=""})
          record: kubecost_cluster_memory_working_set_bytes
      EOT
    }
    Savings = {
      name = "Savings"
      data = <<-EOT
      groups:
      - name: Savings
        rules:
        - expr: sum(avg(kube_pod_owner{owner_kind!="DaemonSet"}) by (pod) * sum(container_cpu_allocation) by (pod))
          record: kubecost_savings_cpu_allocation
          labels:
            daemonset: "false"
        - expr: sum(avg(kube_pod_owner{owner_kind="DaemonSet"}) by (pod) * sum(container_cpu_allocation) by (pod)) / sum(kube_node_info)
          record: kubecost_savings_cpu_allocation
          labels:
            daemonset: "true"
        - expr: sum(avg(kube_pod_owner{owner_kind!="DaemonSet"}) by (pod) * sum(container_memory_allocation_bytes) by (pod))
          record: kubecost_savings_memory_allocation_bytes
          labels:
            daemonset: "false"
        - expr: sum(avg(kube_pod_owner{owner_kind="DaemonSet"}) by (pod) * sum(container_memory_allocation_bytes) by (pod)) / sum(kube_node_info)
          record: kubecost_savings_memory_allocation_bytes
          labels:
            daemonset: "true"
      EOT
    }
  }
}

module "prometheus_amp" {
  source = "terraform-aws-modules/managed-service-prometheus/aws"

  rule_group_namespaces = {
    CPU = {
      name = "CPU"
      data = <<-EOT
      groups:
      - name: CPU
        rules:
        - expr: sum(rate(container_cpu_usage_seconds_total{container!=""}[5m]))
          record: cluster:cpu_usage:rate5m
        - expr: rate(container_cpu_usage_seconds_total{container!=""}[5m])
          record: cluster:cpu_usage_nosum:rate5m
        - expr: avg(irate(container_cpu_usage_seconds_total{container!="POD", container!=""}[5m])) by (container,pod,namespace)
          record: kubecost_container_cpu_usage_irate
        - expr: sum(container_memory_working_set_bytes{container!="POD",container!=""}) by (container,pod,namespace)
          record: kubecost_container_memory_working_set_bytes
        - expr: sum(container_memory_working_set_bytes{container!="POD",container!=""})
          record: kubecost_cluster_memory_working_set_bytes
      EOT
    }
    Savings = {
      name = "Savings"
      data = <<-EOT
      groups:
      - name: Savings
        rules:
        - expr: sum(avg(kube_pod_owner{owner_kind!="DaemonSet"}) by (pod) * sum(container_cpu_allocation) by (pod))
          record: kubecost_savings_cpu_allocation
          labels:
            daemonset: "false"
        - expr: sum(avg(kube_pod_owner{owner_kind="DaemonSet"}) by (pod) * sum(container_cpu_allocation) by (pod)) / sum(kube_node_info)
          record: kubecost_savings_cpu_allocation
          labels:
            daemonset: "true"
        - expr: sum(avg(kube_pod_owner{owner_kind!="DaemonSet"}) by (pod) * sum(container_memory_allocation_bytes) by (pod))
          record: kubecost_savings_memory_allocation_bytes
          labels:
            daemonset: "false"
        - expr: sum(avg(kube_pod_owner{owner_kind="DaemonSet"}) by (pod) * sum(container_memory_allocation_bytes) by (pod)) / sum(kube_node_info)
          record: kubecost_savings_memory_allocation_bytes
          labels:
            daemonset: "true"
      EOT
    }
  }

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

## EKS Prom AMPCost
module "eks_prom_ampcost" {
  source = "terraform-aws-modules/eks/aws"

  cluster_name = format("%s-prom-ampcost-eks", local.name)
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
      service_account_role_arn = module.irsa_prom_ampcost_ebs_csi_plugin.iam_role_arn
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

module "irsa_prom_ampcost_ebs_csi_plugin" {
  source = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"

  role_name             = format("%s-irsa-prom-ampcost-ebs-csi-plugin", local.name)
  attach_ebs_csi_policy = true

  oidc_providers = {
    main = {
      provider_arn               = module.eks_prom_ampcost.oidc_provider_arn
      namespace_service_accounts = ["kube-system:ebs-csi-controller-sa", "kube-system:ebs-csi-node-sa"]
    }
  }
}

## EKS Prom AMPCost / Load Balancer Controller
module "irsa_prom_ampcost_load_balancer_controller" {
  source = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"

  role_name                              = format("%s-irsa-prom-ampcost-aws-load-balancer-controller", local.name)
  attach_load_balancer_controller_policy = true

  oidc_providers = {
    main = {
      provider_arn               = module.eks_prom_ampcost.oidc_provider_arn
      namespace_service_accounts = ["kube-system:aws-load-balancer-controller"]
    }
  }
}

resource "helm_release" "prom_ampcost_aws_load_balancer_controller" {
  provider = helm.prom-ampcost

  namespace  = "kube-system"
  name       = "aws-load-balancer-controller"
  chart      = "aws-load-balancer-controller"
  repository = "https://aws.github.io/eks-charts"
  version    = "v1.6.2"

  set {
    name  = "clusterName"
    value = module.eks_prom_ampcost.cluster_name
  }
  set {
    name  = "serviceAccount.annotations.eks\\.amazonaws\\.com/role-arn"
    value = module.irsa_prom_ampcost_load_balancer_controller.iam_role_arn
  }

  depends_on = [
    module.irsa_prom_ampcost_load_balancer_controller,
  ]
}

## EKS Prom AMPCost / Kubecost 
module "irsa_prom_ampcost_prometheus" {
  source = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"

  role_name                                       = format("%s-prom-ampcost-prometheus", local.name)
  attach_amazon_managed_service_prometheus_policy = true

  oidc_providers = {
    main = {
      provider_arn               = module.eks_prom_ampcost.oidc_provider_arn
      namespace_service_accounts = ["kubecost:cost-analyzer-prometheus-server"]
    }
  }
}

resource "helm_release" "prom_ampcost_kubecost" {
  provider = helm.prom-ampcost

  namespace        = "kubecost"
  create_namespace = true

  name       = "cost-analyzer"
  chart      = "cost-analyzer"
  repository = "https://kubecost.github.io/cost-analyzer"
  version    = "1.108.0"
 
  values = [
    templatefile("${path.module}/helm-values/kubecost-prom-ampcost.yaml",
      {
        region                    = local.region
        amp_remote_write_endpoint = format("https://aps-workspaces.%s.amazonaws.com/workspaces/%s/api/v1/remote_write", local.region, module.prometheus_prom_ampcost.workspace_id)
      }
    )
  ]

  set {
    name  = "clusterName"
    value = module.eks_prom_ampcost.cluster_name
  }
  set {
    name  = "prometheus.serviceAccounts.server.annotations.eks\\.amazonaws\\.com/role-arn"
    value = module.irsa_prom_ampcost_prometheus.iam_role_arn
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

data "kubectl_file_documents" "adot_amp_adot_amp" {
  content = templatefile("${path.module}/manifests/adot-amp.yaml",
    {
      region                    = local.region
      amp_role_arn              = module.irsa_adot_amp_adot_collector_amp.iam_role_arn
      amp_remote_write_endpoint = format("https://aps-workspaces.%s.amazonaws.com/workspaces/%s/api/v1/remote_write", local.region, module.prometheus_adot_amp.workspace_id)
    }
  )
}

resource "kubectl_manifest" "adot_amp_adot_amp" {
  provider = kubectl.adot-amp

  for_each = data.kubectl_file_documents.adot_amp_adot_amp.manifests
  yaml_body = each.value
}

resource "helm_release" "adot_amp_node_exporter" {
  provider = helm.adot-amp

  namespace        = "kubecost"
  create_namespace = true

  name       = "prometheus-node-exporter"
  chart      = "prometheus-node-exporter"
  repository = "https://prometheus-community.github.io/helm-charts"
  version    = "4.29.0"
}

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
      cluster_arn        = module.eks_amp.cluster_arn
      subnet_ids         = module.vpc.private_subnets
      security_group_ids = [module.eks_amp.node_security_group_id]
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
  scrape_timeout: 10s
scrape_configs:
- job_name: 'kubernetes-apiservers'
  scheme: https
  kubernetes_sd_configs:
  - role: endpoints
  tls_config:
    ca_file: /var/run/secrets/kubernetes.io/serviceaccount/ca.crt
    insecure_skip_verify: true
  bearer_token_file: /var/run/secrets/kubernetes.io/serviceaccount/token
  relabel_configs:
  - source_labels: [__meta_kubernetes_namespace, __meta_kubernetes_service_name, __meta_kubernetes_endpoint_port_name]
    action: keep
    regex: default;kubernetes;https
- job_name: 'kubernetes-nodes'
  scheme: https
  kubernetes_sd_configs:
  - role: node
  tls_config:
    ca_file: /var/run/secrets/kubernetes.io/serviceaccount/ca.crt
    insecure_skip_verify: true
  bearer_token_file: /var/run/secrets/kubernetes.io/serviceaccount/token
  relabel_configs:
  - action: labelmap
    regex: __meta_kubernetes_node_label_(.+)
  - target_label: __address__
    replacement: kubernetes.default.svc:443
  - source_labels: [__meta_kubernetes_node_name]
    regex: (.+)
    target_label: __metrics_path__
    replacement: /api/v1/nodes/$1/proxy/metrics
- job_name: 'kubernetes-nodes-cadvisor'
  scheme: https
  kubernetes_sd_configs:
  - role: node
  tls_config:
    ca_file: /var/run/secrets/kubernetes.io/serviceaccount/ca.crt
    insecure_skip_verify: true
  bearer_token_file: /var/run/secrets/kubernetes.io/serviceaccount/token
  relabel_configs:
  - action: labelmap
    regex: __meta_kubernetes_node_label_(.+)
  - target_label: __address__
    replacement: kubernetes.default.svc:443
  - source_labels: [__meta_kubernetes_node_name]
    regex: (.+)
    target_label: __metrics_path__
    replacement: /api/v1/nodes/$1/proxy/metrics/cadvisor
- job_name: 'kubernetes-service-endpoints'
  honor_labels: true
  kubernetes_sd_configs:
  - role: endpoints
  relabel_configs:
  - source_labels: [__meta_kubernetes_service_annotation_prometheus_io_scrape]
    action: keep
    regex: true
  - source_labels: [__meta_kubernetes_service_annotation_prometheus_io_scrape_slow]
    action: drop
    regex: true
  - source_labels: [__meta_kubernetes_service_annotation_prometheus_io_scheme]
    action: replace
    target_label: __scheme__
    regex: (https?)
  - source_labels: [__meta_kubernetes_service_annotation_prometheus_io_path]
    action: replace
    target_label: __metrics_path__
    regex: (.+)
  - source_labels: [__address__, __meta_kubernetes_service_annotation_prometheus_io_port]
    action: replace
    target_label: __address__
    regex: (.+?)(?::\d+)?;(\d+)
    replacement: $1:$2
  - action: labelmap
    regex: __meta_kubernetes_service_annotation_prometheus_io_param_(.+)
    replacement: __param_$1
  - action: labelmap
    regex: __meta_kubernetes_service_label_(.+)
  - source_labels: [__meta_kubernetes_namespace]
    action: replace
    target_label: namespace
  - source_labels: [__meta_kubernetes_service_name]
    action: replace
    target_label: service
  - source_labels: [__meta_kubernetes_pod_node_name]
    action: replace
    target_label: node
- job_name: 'kubecost'
  scrape_interval: 60s
  scrape_timeout: 60s
  metrics_path: /metrics
  scheme: http
  kubernetes_sd_configs:
  - role: pod
  relabel_configs:
  - source_labels: [__meta_kubernetes_pod_label_app_kubernetes_io_instance]
    action: keep
    regex:  cost-analyzer
  - source_labels: [__meta_kubernetes_pod_label_app_kubernetes_io_name]
    action: keep
    regex:  cost-analyzer
- job_name: 'kubecost-networking'
  kubernetes_sd_configs:
  - role: pod
  relabel_configs:
  - source_labels: [__meta_kubernetes_pod_label_app_kubernetes_io_instance]
    action: keep
    regex:  kubecost
  - source_labels: [__meta_kubernetes_pod_label_app_kubernetes_io_name]
    action: keep
    regex:  network-costs
EOT
}

data "kubectl_file_documents" "adot_amp_scrapper_role" {
  content = file("${path.module}/manifests/amp-scrapper-role.yaml")
}

resource "kubectl_manifest" "adot_amp_scrapper_role" {
  provider = kubectl.amp

  for_each = data.kubectl_file_documents.adot_amp_scrapper_role.manifests
  yaml_body = each.value
}

resource "helm_release" "amp_node_exporter" {
  provider = helm.amp

  namespace        = "kubecost"
  create_namespace = true

  name       = "prometheus-node-exporter"
  chart      = "prometheus-node-exporter"
  repository = "https://prometheus-community.github.io/helm-charts"
  version    = "4.29.0"
}
