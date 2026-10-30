# Main component: platform glue + the shared dependency-free core.
# The core (../../proto) is byte-identical logic to the Arduino build and
# the host protocol test; only transport + boot glue differ.
idf_component_register(
    SRCS "main.c" "../../proto/sha256.cpp" "../../proto/obproto.cpp"
    INCLUDE_DIRS "." "../../proto"
)
