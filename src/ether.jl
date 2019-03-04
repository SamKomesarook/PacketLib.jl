include("lib.jl")

"The parameters to an Ethernet packet are composites of multiple values, to allow developers a lot of flexibility when crafting a packet."
EtherAddr = Union{UInt8, Array{UInt8}, AbstractString, Int64, Array{Int64}, Base.CodeUnits{UInt8,String}}
EtherType = Union{EtherAddr, UInt16}
EtherPayload = Union{EtherAddr, Packet}

"The base Ethernet structure."
Base.@kwdef mutable struct Ether <: Packet
    dst::EtherAddr = "ff:ff:ff:ff:ff:ff"
    src::EtherAddr = "ff:ff:ff:ff:ff:ff"
    type::EtherType = 9000
    payload::EtherPayload = NoPayload()
end

"Create the raw version of an Ethernet packet. Returns an integer array of raw values to be sent."
function raw(p::Ether)
    return vcat(etheraddr_raw(p.dst),etheraddr_raw(p.src),ethertype_raw(p.type), etherpayload_raw(p.payload))
end

"Create the raw ethernet payload."
function etherpayload_raw(e::EtherPayload)
    if isa(e, NoPayload)
        return []
    elseif isa(e, Packet)
        return raw(e)
    else
        if isa(e, UInt8)
            return [Int(e)]
        elseif isa(e, Array{UInt8})
            return e
        elseif isa(e, AbstractString)
            return [Int(i) for i in Base.CodeUnits(e)]
        elseif isa(e, Int64)
            [Int(e)]
        elseif isa(e, Array{Int64})
            return e
        else
            [Int(i) for i in e]
        end
    end
end

"Create the raw ethernet type."
function ethertype_raw(e::EtherType)
    if isa(e, UInt8)
        return append!([Int(e)], [0x00])
    elseif isa(e, Array{UInt8})
        while length(e) < 2
            append!(e, 0x00)
        end
        return [Int(i) for i in e]
    elseif isa(e, AbstractString)
        if length(string(e)) == 4
            return [parse(Int, e[1:2], base=16), parse(Int, e[3:4], base=16)]
        else
            #TODO::STRING COULD BE TYPE DESCRIPTION
            error("NOT IMPLEMENTED YET")
        end
    elseif isa(e, Int64)
        @assert length(string(e)) == 4
        return [parse(Int, string(e)[1:2], base=16), parse(Int, string(e)[3:4], base=16)]
    elseif isa(e, Array{Int64})
        while length(e) < 2
            append!(e, 0)
        end
        return e
    elseif isa(e, UInt16)
        #TODO::0x9000?
        error("NOT IMPLEMENTED YET")
    else
        e = Array{UInt8}(e)
        while length(e) < 2
            append!(e, 0x00)
        end
        return [Int(i) for i in e]
    end
end

"Create the raw ethernet address."
function etheraddr_raw(e::EtherAddr)
    if isa(e, UInt8)
        return append!([Int(e)], [0x00 for i in 1:5])
    elseif isa(e, Array{UInt8})
        while length(e) < 6
            append!(e, 0x00)
        end
        return [Int(i) for i in e]
    elseif isa(e, AbstractString)
        s = split(e, ":")
        a = [parse(Int, i, base=16) for i in s]
        if length(a) != 6
            return [Int(i) for i in Base.CodeUnits(e)]
        end
        return a
    elseif isa(e, Int64)
        return append!([Int(e)], [0 for i in 1:5])
    elseif isa(e, Array{Int64})
        while length(e) < 6
            append!(e, 0)
        end
        return e
    else
        e = Array{UInt8}(e)
        while length(e) < 6
            append!(e, 0x00)
        end
        return [Int(i) for i in e]
    end
end

"Send the packet."
function send(p::Packet, iface::String="en0", loop::Bool=false, count::Int=1, delay::Float64=0.0)
    if isa(p, Ether)
        l2 = 1
    else
        l2 = 0
    end
    p = raw(p)
    if loop
        count = 0
    end
    return ccall((:send_l, "src/packetlib.so"), Int64, (Ptr{UInt8}, Int64, Int64, Int64, Float64, Cstring, ), convert(Array{UInt8,1}, p), length(p), l2, count, delay, iface)
end
