def new_client_context(
    client_name,
    ip_addr,
    rpc_port_num,
    service_name="",
    metrics_info=None,
):
    return struct(
        service_name=service_name,
        client_name=client_name,
        ip_addr=ip_addr,
        rpc_port_num=rpc_port_num,
        metrics_info=metrics_info,
    )
