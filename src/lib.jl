"Abstract superclass for all packets."
abstract type Packet end
"Struct designating an empty payload."
struct NoPayload <: Packet end #TODO:: Could nil simply be used instead?
