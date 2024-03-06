def get_enr_for_node(plan, service_name, port_id):
    recipe = PostHttpRequestRecipe(
        endpoint="",
        body='{"method":"discv5_nodeInfo","params":[],"id":1,"jsonrpc":"2.0"}',
        content_type="application/json",
        port_id=port_id,
        extract={
            "enr": ".result.enr",
        },
    )
    response = plan.wait(
        recipe=recipe,
        field="extract.enr",
        assertion="!=",
        target_value="",
        timeout="15m",
        service_name=service_name,
    )
    return response["extract.enr"]
