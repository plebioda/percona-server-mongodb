load("//bazel/platforms:remote_execution_containers.bzl", "REMOTE_EXECUTION_CONTAINERS")

def setup_platform(arch, distro_or_os, cache_silo):
    exec_properties = {
        "container-image": REMOTE_EXECUTION_CONTAINERS[distro_or_os]["container-url"],
        "dockerNetwork": "standard",
    }
    if cache_silo:
        exec_properties.update({"cache-silo-key": distro_or_os + "_" + arch})

    native.platform(
        name = distro_or_os + "_" + arch + cache_silo,
        constraint_values = [
            "@platforms//os:linux",
            "@platforms//cpu:arm64" if arch == "arm64" else "@platforms//cpu:x86_64",
            ":" + distro_or_os,
            ":use_mongo_toolchain",
        ],
        exec_properties = exec_properties,
    )
