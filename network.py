import libnmstate
from libnmstate.schema import Interface
from libnmstate.schema import InterfaceState

libnmstate.apply(
{
    Interface.KEY: [
        {
            Interface.NAME: 'br-gen',
            Interface.STATE: InterfaceState.ABSENT,
        }
    ]
})

