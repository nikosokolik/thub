import bridge_utils as _bridge_utils
from tap_utils import iff_up as _iff_up, iff_down as _iff_down


class Bridge(object):
    def __init__(self, name=None):
        if name == None:
            name = b'vph_br'
        elif type(name) is str:
            name = name.encode()
        self._name = name
        self._connected_interfaces = []

    def add_interface(self, interface_name):
        if interface_name not in self._connected_interfaces:
            _bridge_utils.add_interface(self._name, interface_name)
            self._connected_interfaces.append(interface_name)

    def delete_interface(self, interface_name):
        if interface_name in self._connected_interfaces:
            _bridge_utils.del_inerface(self._name, interface_name)
            self._connected_interfaces.remove(interface_name)

    def create_bridge(self):
        _bridge_utils.add_bridge(self._name)
        _iff_up(self._name)

    def destroy_bridge(self):
        for connected_interface in self._connected_interfaces:
            self.delete_interface(connected_interface)
        _iff_down(self._name)
        _bridge_utils.delete_bridge(self._name)

    def __enter__(self):
        self.create_bridge()
        return self

    def __exit__(self, type=None, value=None, tb=None):
        self.destroy_bridge()
