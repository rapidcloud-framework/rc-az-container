module "az_aks_rcdemo" {
    source = "./aks_cluster"
    profile = "demo_rc"
    name = "rcdemo"
    location = "eastus"
    resource_group = "sk_demo_rg"
    auto_upgrade = true
    aks_version = "1.26"
    private_cluster_enabled = true
    api_server_vnet_integrated_enabled = false
    desired_size = 2
    max_size = 3
    min_size = 1
    vm_size = "Standard_DS2_v2"
    node_pool_zones = ["1","2"]
    azure_cni_enabled = true
    network_policy = "azure"
    vnet_subnet_id = "/subscriptions/0cea775f-c244-435a-a253-10f9f0f0fa26/resourceGroups/sk_demo_rg/providers/Microsoft.Network/virtualNetworks/aksrcvnet/subnets/default"
    service_cidr = "10.30.1.0/24"
    dns_service_ip = "10.30.1.2"
    aad_enabled = true
    azure_rbac_enabled = true
    rbac_aad_admin_group_object_ids = ["6e92b0da-9e7e-46c6-9e9c-36eca8760ce5"]  
    log_analytics_workspace_id = "/subscriptions/0cea775f-c244-435a-a253-10f9f0f0fa26/resourceGroups/rg-test-dev/providers/Microsoft.OperationalInsights/workspaces/wor-test-dev"

    # identity = "{{identity}}"
    # node_count = "{{node_count}}"
    # node_size = "{{node_size}}"
    # enable_autoscaler = "{{enable_autoscaler}}"
    # dns_prefix = "{{dns_prefix}}"
    # private_cluster = "{{private_cluster}}"
    # {% if params['tags'] is defined %}
    # tags = {{ params['tags'] }}
    # {% endif %}
}