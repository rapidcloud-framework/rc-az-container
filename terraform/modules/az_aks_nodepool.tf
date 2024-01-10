module "az_aks_np_demo" {
    source = "./aks_node_pool"
    profile = "demo_rc"
    env = "dev"
    workload = "demo"
    cmd_id = "xyz"
    name = "rcdemonp"
    cluster_id = "/subscriptions/0cea775f-c244-435a-a253-10f9f0f0fa26/resourceGroups/sk_demo_rg/providers/Microsoft.ContainerService/managedClusters/rcdemo"
    cluster_name = "rcdemo"
    os_sku = "Windows2019"
    os_type = "Windows"
    use_spot_instance = true
    subnet_id = "/subscriptions/0cea775f-c244-435a-a253-10f9f0f0fa26/resourceGroups/sk_demo_rg/providers/Microsoft.Network/virtualNetworks/aksrcvnet/subnets/default"
    node_labels = {
        "workload" = "demo"
    }
    node_taints = [ "workload=demorc:NoSchedule" ]
}