import libnmstate
from libnmstate.schema import Interface
from libnmstate.schema import InterfaceType
from libnmstate.schema import InterfaceState
from libnmstate.schema import OVSBridge


libnmstate.apply(
{
    Interface.KEY: [
        {
            Interface.NAME: 'br-gen',
            Interface.STATE: InterfaceState.UP,
            Interface.TYPE: OVSBridge.TYPE,
            OVSBridge.CONFIG_SUBTREE: {
                OVSBridge.PORT_SUBTREE: [
                    {
                        OVSBridge.Port.NAME: 'gen',
                    }
                ]
            }
        },
    ]
})