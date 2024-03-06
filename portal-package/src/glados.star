constants = import_module("./utils/constants.star")
glados = import_module("./glados/glados_launcher.star")

def launch(
    plan,
    glados_config,
    bootnode_enrs,
):
    context = glados.launch(
        plan,
        glados_config,
        bootnode_enrs
    )
    return context
