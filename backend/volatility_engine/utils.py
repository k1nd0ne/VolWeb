from inspect import _empty
from volatility_engine.models import VolatilityPlugin
import datetime, hashlib, io, tempfile, os, stat, logging, volatility3, urllib.parse, s3fs, json
from typing import Dict, Any, List, Tuple
from volatility3.framework import interfaces
from volatility3.framework.interfaces.context import ModuleInterface
from volatility3.framework.interfaces.layers import (
    DataLayerInterface,
    TranslationLayerInterface,
)
from volatility3.framework.configuration import requirements
from volatility3.cli.text_renderer import (
    CLIRenderer,
    optional,
    quoted_optional,
    hex_bytes_as_text,
    display_disassembly,
    multitypedata_as_text,
)
from volatility3.framework.renderers import format_hints
from backend.keyconfig import Secrets
from evidences.models import Evidence
from volatility3.framework import automagic, constants, exceptions
from volatility3.cli import MuteProgress
from volatility3.framework.layers.cloudstorage import S3FileSystemHandler
from volatility3.plugins.windows import modules, ssdt
from typing import Optional

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def fix_permissions(output_path):
    try:
        if not os.path.exists(output_path):
            logger.error(f"Output path does not exist: {output_path}")
            return
        for filename in os.listdir(output_path):
            filepath = os.path.join(output_path, filename)
            if os.path.isfile(filepath):
                try:
                    current_permissions = stat.S_IMODE(os.lstat(filepath).st_mode)
                    if not current_permissions & stat.S_IROTH:
                        os.chmod(filepath, current_permissions | stat.S_IROTH)
                        logger.info(f"Updated permissions for: {filepath}")
                except Exception as e:
                    logger.error(f"Error changing permissions for {filepath}: {e}")
            else:
                logger.warning(f"Skipping {filepath}, not a file.")
    except Exception as e:
        logger.error(f"Error when updating permissions: {e}")


class GraphException(Exception):
    """Class to allow filtering of the graph generation errors"""


def generate_windows_network_graph(data):
    graph_data = {"nodes": [], "edges": []}
    node_id_map = {}

    for entry in data:
        pid = entry["PID"]
        local_address = entry["LocalAddr"]
        local_port = entry["LocalPort"]
        foreign_address = entry["ForeignAddr"]
        foreign_port = entry["ForeignPort"]

        # Node data for the process
        if pid not in node_id_map:
            node_data_1 = {
                "id": pid,
                "Process": entry["Owner"],
                "LocalAddr": local_address,
                "LocalPorts": [local_port],
            }
            graph_data["nodes"].append(node_data_1)
            node_id_map[pid] = node_data_1
        else:
            # If the process is already a node, just add the local port if it's not already there
            if local_port not in node_id_map[pid]["LocalPorts"]:
                node_id_map[pid]["LocalPorts"].append(local_port)

        # Node data for the foreign address
        if foreign_address not in node_id_map:
            node_data_2 = {
                "id": foreign_address,
                "ForeignPorts": [foreign_port],
            }
            graph_data["nodes"].append(node_data_2)
            node_id_map[foreign_address] = node_data_2
        else:
            if "ForeignPorts" not in node_id_map[foreign_address]:
                node_id_map[foreign_address]["ForeignPorts"] = []
            if foreign_port not in node_id_map[foreign_address]["ForeignPorts"]:
                node_id_map[foreign_address]["ForeignPorts"].append(foreign_port)

        # Edge data
        edge_data = {"from": pid, "to": foreign_address}
        if edge_data not in graph_data["edges"]:
            graph_data["edges"].append(edge_data)

    return graph_data


def generate_linux_network_graph(data):
    graph_data = {"nodes": [], "edges": []}
    node_id_map = {}
    for entry in data:
        if "AF_INET" in entry["Family"]:
            pid = entry["Pid"]
            local_address = entry["Source Addr"]
            local_port = entry["Source Port"]
            foreign_address = entry["Destination Addr"]
            foreign_port = entry["Destination Port"]

            # Node data for the process
            if pid not in node_id_map:
                node_data_1 = {
                    "id": pid,
                    "Process": pid,
                    "LocalAddr": local_address,
                    "LocalPorts": [local_port],
                }
                graph_data["nodes"].append(node_data_1)
                node_id_map[pid] = node_data_1
            else:
                # If the process is already a node, just add the local port if it's not already there
                if local_port not in node_id_map[pid]["LocalPorts"]:
                    node_id_map[pid]["LocalPorts"].append(local_port)

            # Node data for the foreign address
            if foreign_address not in node_id_map:
                node_data_2 = {
                    "id": foreign_address,
                    "ForeignPorts": [foreign_port],
                }
                graph_data["nodes"].append(node_data_2)
                node_id_map[foreign_address] = node_data_2
            else:
                if "ForeignPorts" not in node_id_map[foreign_address]:
                    node_id_map[foreign_address]["ForeignPorts"] = []
                if foreign_port not in node_id_map[foreign_address]["ForeignPorts"]:
                    node_id_map[foreign_address]["ForeignPorts"].append(foreign_port)

            # Edge data
            edge_data = {"from": pid, "to": foreign_address}
            if edge_data not in graph_data["edges"]:
                graph_data["edges"].append(edge_data)

    return graph_data


def build_timeline(data):
    timeline = []
    nb_event = 1
    actual_date = ""
    try:
        print(data)
        saved_date = data[0]["Created Date"]
    except:
        raise GraphException("Could not generate timeline graph")
    for i in data:
        try:
            actual_date = str(i["Created Date"])
            if actual_date != saved_date:
                timeline.append([saved_date, nb_event])
                saved_date = actual_date
                nb_event = 1
            else:
                nb_event += 1
        except:
            raise GraphException("Could not generate timeline graph")
    return timeline


@staticmethod
def volweb_open(req: urllib.request.Request) -> Optional[Any]:
    if req.type == "s3":
        object_uri = "://".join(req.full_url.split("://")[1:])
        try:
            instance = Evidence.objects.get(url=req.full_url)
            if instance.source == "AWS":
                endpoint_url = f"https://s3.dualstack.{instance.region}.amazonaws.com"
            else:
                endpoint_url = instance.endpoint
            return s3fs.S3FileSystem(
                key=instance.access_key_id,
                secret=instance.access_key,
                client_kwargs={
                    "region_name": instance.region,
                    "endpoint_url": endpoint_url,
                },
            ).open(object_uri)
        except Evidence.DoesNotExist:
            return s3fs.S3FileSystem().open(object_uri)
    return None


def volweb_add_module(self, module: ModuleInterface) -> None:
    """Adds a module to the module collection

    This will throw an exception if the required dependencies are not met

    Args:
        module: the module to add to the list of modules (based on module.name)
    """
    if module.name in self._modules:
        return
    self._modules[module.name] = module


def volweb_add_layer(self, layer: DataLayerInterface) -> None:
    """Adds a layer to memory model.

    This will throw an exception if the required dependencies are not met

    Args:
        layer: the layer to add to the list of layers (based on layer.name)
    """
    if layer.name in self._layers:
        return
    if isinstance(layer, TranslationLayerInterface):
        missing_list = [
            sublayer for sublayer in layer.dependencies if sublayer not in self._layers
        ]
        if missing_list:
            raise exceptions.LayerException(
                layer.name,
                f"Layer {layer.name} has unmet dependencies: {', '.join(missing_list)}",
            )
    self._layers[layer.name] = layer


class DjangoRenderer(CLIRenderer):
    _type_renderers = {
        format_hints.HexBytes: quoted_optional(hex_bytes_as_text),
        interfaces.renderers.Disassembly: quoted_optional(display_disassembly),
        format_hints.MultiTypeData: quoted_optional(multitypedata_as_text),
        bytes: optional(lambda x: " ".join([f"{b:02x}" for b in x])),
        datetime.datetime: lambda x: (
            x.isoformat()
            if not isinstance(x, interfaces.renderers.BaseAbsentValue)
            else None
        ),
        "default": lambda x: x,
    }
    name = "JSON"
    structured_output = True

    def __init__(self, evidence_id: int, plugin):
        self.evidence = Evidence.objects.get(id=evidence_id)
        self.plugin = plugin

    def get_render_options(self) -> List[interfaces.renderers.RenderOption]:
        pass

    def save_to_database(self, result):
        """Outputs the Dict data to our django database"""
        results = False
        if result:
            results = True

        VolatilityPlugin(
            name=self.plugin["name"],
            icon=self.plugin["icon"],
            description=self.plugin["description"],
            evidence=self.evidence,
            artefacts=result,
            category=self.plugin["category"],
            display=self.plugin["display"],
            results=results,
        ).save()

    def render(self, grid: interfaces.renderers.TreeGrid):
        final_output: Tuple[
            Dict[str, List[interfaces.renderers.TreeNode]],
            List[interfaces.renderers.TreeNode],
        ] = ({}, [])

        def visitor(
            node: interfaces.renderers.TreeNode,
            accumulator: Tuple[Dict[str, Dict[str, Any]], List[Dict[str, Any]]],
        ) -> Tuple[Dict[str, Dict[str, Any]], List[Dict[str, Any]]]:
            # Nodes always have a path value, giving them a path_depth of at least 1, we use max just in case
            acc_map, final_tree = accumulator
            node_dict: Dict[str, Any] = {"__children": []}
            for column_index in range(len(grid.columns)):
                column = grid.columns[column_index]
                renderer = self._type_renderers.get(
                    column.type, self._type_renderers["default"]
                )
                data = renderer(list(node.values)[column_index])
                if isinstance(data, interfaces.renderers.BaseAbsentValue):
                    data = None
                node_dict[column.name] = data
            if node.parent:
                acc_map[node.parent.path]["__children"].append(node_dict)
            else:
                final_tree.append(node_dict)
            acc_map[node.path] = node_dict

            return (acc_map, final_tree)

        try:
            if not grid.populated:
                grid.populate(visitor, final_output)
            else:
                grid.visit(
                    node=None, function=visitor, initial_accumulator=final_output
                )
        except Exception as e:
            logger.warning(f"Could not run plugin: {e}")
        self.save_to_database(final_output[1])
        return final_output[1]


class DictRenderer(CLIRenderer):
    """
    Same as JSONRenderer but not dumped into json
    """

    _type_renderers = {
        format_hints.HexBytes: quoted_optional(hex_bytes_as_text),
        interfaces.renderers.Disassembly: quoted_optional(display_disassembly),
        format_hints.MultiTypeData: quoted_optional(multitypedata_as_text),
        bytes: optional(lambda x: " ".join([f"{b:02x}" for b in x])),
        datetime.datetime: lambda x: (
            x.isoformat()
            if not isinstance(x, interfaces.renderers.BaseAbsentValue)
            else None
        ),
        "default": lambda x: x,
    }

    name = "JSON"
    structured_output = True

    def get_render_options(self) -> List[interfaces.renderers.RenderOption]:
        pass

    def render(self, grid: interfaces.renderers.TreeGrid):
        final_output: Tuple[
            Dict[str, List[interfaces.renderers.TreeNode]],
            List[interfaces.renderers.TreeNode],
        ] = ({}, [])

        def visitor(
            node: interfaces.renderers.TreeNode,
            accumulator: Tuple[Dict[str, Dict[str, Any]], List[Dict[str, Any]]],
        ) -> Tuple[Dict[str, Dict[str, Any]], List[Dict[str, Any]]]:
            # Nodes always have a path value, giving them a path_depth of at least 1, we use max just in case
            acc_map, final_tree = accumulator
            node_dict: Dict[str, Any] = {"__children": []}
            for column_index in range(len(grid.columns)):
                column = grid.columns[column_index]
                renderer = self._type_renderers.get(
                    column.type, self._type_renderers["default"]
                )
                data = renderer(list(node.values)[column_index])
                if isinstance(data, interfaces.renderers.BaseAbsentValue):
                    data = None
                node_dict[column.name] = data
            if node.parent:
                acc_map[node.parent.path]["__children"].append(node_dict)
            else:
                final_tree.append(node_dict)
            acc_map[node.path] = node_dict

            return acc_map, final_tree

        if not grid.populated:
            grid.populate(visitor, final_output)
        else:
            grid.visit(node=None, function=visitor, initial_accumulator=final_output)

        return final_output[1]


def file_handler(output_dir):
    class CLIFileHandler(interfaces.plugins.FileHandlerInterface):
        """The FileHandler from Volatility3 CLI"""

        def _get_final_filename(self):
            """Gets the final filename"""
            if output_dir is None:
                raise TypeError("Output directory is not a string")
            os.makedirs(output_dir, exist_ok=True)

            pref_name_array = self.preferred_filename.split(".")
            filename, extension = (
                os.path.join(output_dir, ".".join(pref_name_array[:-1])),
                pref_name_array[-1],
            )
            output_filename = f"{filename}.{extension}"

            if os.path.exists(output_filename):
                os.remove(output_filename)
            return output_filename

    class CLIDirectFileHandler(CLIFileHandler):
        """We want to save our files directly to disk"""

        def __init__(self, filename: str):
            if not os.path.exists(output_dir):
                os.makedirs(
                    output_dir, exist_ok=True
                )  # We create the directory if it does not exists.
            fd, self._name = tempfile.mkstemp(
                suffix=".vol3", prefix="tmp_", dir=output_dir
            )
            self._file = io.open(fd, mode="w+b")
            CLIFileHandler.__init__(self, filename)
            for item in dir(self._file):
                if not item.startswith("_") and not item in [
                    "closed",
                    "close",
                    "mode",
                    "name",
                ]:
                    setattr(self, item, getattr(self._file, item))

        def __getattr__(self, item):
            return getattr(self._file, item)

        @property
        def closed(self):
            return self._file.closed

        @property
        def mode(self):
            return self._file.mode

        @property
        def name(self):
            return self._file.name

        def close(self):
            """Closes and commits the file (by moving the temporary file to the correct name"""
            # Don't overcommit
            if self._file.closed:
                return

            self._file.close()
            output_filename = self._get_final_filename()
            os.rename(self._name, output_filename)

    return CLIDirectFileHandler


S3FileSystemHandler.default_open = volweb_open  # This is to set the correct AWS endpoint url when the source bucket is of type AWS.
volatility3.symbols.__path__ = [
    os.path.abspath(f"media/symbols")
] + constants.SYMBOL_BASEPATHS  # This is to include the volweb symbols imported by the users.
interfaces.context.ModuleContainer.add_module = volweb_add_module  # A module requirement already present is throwing an exeception, we don't want this.
interfaces.layers.LayerContainer.add_layer = volweb_add_layer  # An already present layer is throwing an exception, we don't want this either.
