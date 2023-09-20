# simplified interface to the LLVM disassembler

function llvm_create_disassembler()
    triplet = Base.BinaryPlatforms.host_triplet()
    return ccall(:jl_LLVMCreateDisasm,
        Ptr{Cvoid},
        (Cstring, Ptr{Cvoid}, Cint, Ptr{Cvoid}, Ptr{Cvoid}),
        triplet, C_NULL, 0, C_NULL, C_NULL)
end

function nullstring!(x::Vector{UInt8})
    i = findfirst(iszero, x)
    SubString(String(x),1,i-1)
end

function llvm_disassemble_instruction(disassembler, data::AbstractVector{UInt8}, pc::UInt64)
    buf = zeros(UInt8, 256)
    sz = ccall(:jl_LLVMDisasmInstruction,
            Csize_t,
            (Ptr{Cvoid}, Ptr{UInt8}, UInt64, UInt64, Ptr{Cchar}, Csize_t),
            disassembler, data, length(data), pc, buf, length(buf))
    
    return nullstring!(buf), sz
end

function llvm_disassemble_multiple(disassembler, data::AbstractVector{UInt8}, pc::UInt64)
    addrs, instrs = UInt64[], String[]

    offset = 0
    while offset < length(data)
        offset_data = @view data[begin+offset:end]
        str, sz = llvm_disassemble_instruction(disassembler, offset_data, pc + offset)

        push!(addrs, pc + offset)
        push!(instrs, str)

        offset += sz
    end

    return addrs, instrs
end

function llvm_disassemble_range(disassembler, start::UInt64, stop::UInt64)
    data = zeros(UInt8, stop - start)

    Base.unsafe_copyto!(pointer(data), Ptr{UInt8}(start), length(data))

    return llvm_disassemble_multiple(disassembler, data, start)
end

function print_disassembled(addrs, instrs)
    for (addr, instr) in zip(addrs, instrs)
        println("$(string(addr, base=16, pad=8)): $instr")
    end
end

function create_addr_ranges(addrs, maxgap=40)
    addrs = sort(addrs)
    
    ranges = [addrs[begin] => addrs[begin]]
    for addr in @view addrs[begin+1:end]
        if addr > ranges[end].second + maxgap
            push!(ranges, addr => addr)
        else
            ranges[end] = (ranges[end].first => addr)
        end
    end
    
    ranges
end
