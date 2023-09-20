module ProfileTools

using Profile
using CodeTracking
using StatsBase
using InteractiveUtils
using REPL.TerminalMenus

include("llvmdis.jl")

export @perf


const IPtr = UInt64

abstract type ProfiledFunction end

struct ProfiledCFunction <: ProfiledFunction
    name::Symbol
    ips::Vector{IPtr}
    location::String
end

struct ProfiledJuliaFunction <: ProfiledFunction
    mi::Core.MethodInstance
    ips::Vector{IPtr}
end

name(pf::ProfiledFunction) = pf.name
location(pf::ProfiledFunction) = pf.location
nsamples(pf::ProfiledFunction) = length(pf.ips)

name(pf::ProfiledJuliaFunction) = pf.mi.def.name
function location(pf::ProfiledJuliaFunction)
    fname, line = functionloc(pf.mi)
    "$fname:$line"
end

@kwdef struct ProfileConfig
    c_funcs::Bool = false
    precompile::Bool = true
end

mutable struct ProfileMenu <: TerminalMenus._ConfiguredMenu{TerminalMenus.Config}
    options::Vector{ProfiledFunction}
    total_samples::Int

    config::TerminalMenus.Config
    pagesize::Int
    pageoffset::Int
    selected::Int
end

function ProfileMenu(options::Vector{ProfiledFunction}, total_samples; kwargs...)
    ProfileMenu(options, total_samples, TerminalMenus.Config(; kwargs...), 20, 0, -1)
end

TerminalMenus.options(m::ProfileMenu) = m.options
TerminalMenus.cancel(m::ProfileMenu) = m.selected = -1

function TerminalMenus.pick(menu::ProfileMenu, cursor::Int)
    menu.selected = cursor
    return true #break out of the menu
end

function TerminalMenus.writeline(buf::IOBuffer, menu::ProfileMenu, idx::Int, iscursor::Bool)
    func = menu.options[idx]

    pct = round(100 * nsamples(func) / menu.total_samples, digits=1)
    pct_color = (pct >= 5 ? (:red) : (pct >= 0.5 ? (:green) : (:normal)))

    buf_colored = IOContext(buf, :color => true)
    print(buf_colored, "(")
    printstyled(buf_colored, "$pct%", color=pct_color)
    print(buf_colored, ") ")
    func_color = func isa ProfiledJuliaFunction ? (:light_cyan) : (:light_magenta)
    printstyled(buf_colored, name(func), color=func_color, bold=true)
    _, rest = splitdir(location(func))
    printstyled(buf_colored, " $rest", color=:light_black)
end

function parse_macro_args(raw_args)
    args, kwargs = [], Dict()
    for el in raw_args
        if Meta.isexpr(el, :(=))
            kwargs[el.args[1]] = el.args[2]
        else
            push!(args, el)
        end
    end
    
    bad = setdiff(keys(kwargs), fieldnames(ProfileConfig))
    !isempty(bad) && throw(ArgumentError("Unknown arguments: $(join(repr.(bad), bad))"))

    for (k, v) in kwargs
        (v isa fieldtype(ProfileConfig, k)) || throw(ArgumentError("Bad argument type: $k"))
    end
    
    return ProfileConfig(; kwargs...)
end

macro perf(expr, args...)
    conf = parse_macro_args(args)

    sym = gensym("profilee")
    fn_def = quote
        @noinline $(sym)() = Base.donotdelete($expr)
    end
    Core.eval(__module__, fn_def)

    quote
        len_start = Profile.len_data()
        $(conf.precompile) ? $(esc(sym))() : nothing
        Profile.@profile $(esc(sym))()
        len_end = Profile.len_data()

        printperf($conf, len_start+1, len_end)
    end
end

function paged_io(func, title="Profile Data - (q) to quit")
    io = IOBuffer()
    io_colored = IOContext(io, :color => true)

    func(io_colored)
    flush(io)
    seek(io, 0)

    run(pipeline(io, `less -R -P "$title"`))
end

function printperf(conf, len_start, len_end)
    ips = terminalIPs(conf, len_start, len_end)

    doit(conf, ips)
    return
end

struct ProfileData
    ips::Vector{IPtr}
    c_ips::Vector{IPtr}
    ip2st::Dict{IPtr, Vector{StackTraces.StackFrame}}
    c_callees::Dict{IPtr, Vector{IPtr}}

    ProfileData() = new([], [], Dict(), Dict())
end

lookup(data::ProfileData, ip::IPtr) = get!(() -> StackTraces.lookup(ip), data.ip2st, ip)

function functionloc_safe(mi)
    fname, line = functionloc(mi)
    fname = isnothing(fname) ? "<unknown>" : fname
    return fname, line
end

function terminalIPs(conf, len_start=1, len_end=nothing)
    samples = Profile.fetch(include_meta=true)
    len_end = isnothing(len_end) ? length(samples) : len_end
    samples = @view samples[len_start:len_end]
    samples = Profile.strip_meta(samples)

    data = ProfileData()

    c_ip::IPtr = 0
    first = true
    for ip in samples
        if first
            st = lookup(data, ip)
            if st[end].from_c
                (c_ip == 0) && (c_ip = ip) # forgot what the point was...
                # push the IP if c functions are being recorded
                # otherwise, continue up until a julia IP
                if conf.c_funcs
                    push!(data.c_ips, ip)
                    first = false
                end
            else
                push!(data.ips, ip)
                #data.c_callees[st]
                first = false
                c_ip = 0
            end
        else
            (ip == 0) && (first = true)
        end
    end

    data
end

function doit(conf, data=terminalIPs(conf))
    mimap = Dict{Core.MethodInstance, Vector{Int}}()
    #stmap = Dict{UInt64, Vector{StackTraces.StackFrame}}()

    cmap = countmap(data.ips)

    functions = ProfiledFunction[]

    ignore = 0
    fromc = 0
    julia_functions = Dict{Core.MethodInstance, ProfiledJuliaFunction}()
    for ip in data.ips
        st = lookup(data, ip)
        if !st[end].from_c
            mi = st[end].linfo
            if !isnothing(mi)
                pf = get!(() -> ProfiledJuliaFunction(mi, []), julia_functions, mi)

                push!(pf.ips, ip)
                !haskey(mimap, mi) && (mimap[mi] = [])
                push!(mimap[mi], st[end].line)
            else
                println("ignoring:: $st")
                #println(">>> $mi")
                ignore += 1
            end
        else
            fromc += 1
            println(">>>>>>>>")
            map(f -> println("$f // $(f.pointer) :: $ip"), st)
        end
    end

    c_funcs = Dict{Symbol, Vector{IPtr}}()
    c_functions = Dict{Symbol, ProfiledCFunction}()
    for ip in data.c_ips
        st = lookup(data, ip)
        frame = st[end]
        name = frame.func
        pf = get!(() -> ProfiledCFunction(name, [], string(frame.file)), c_functions, name)

        push!(pf.ips, ip)
        #c_funcs[frame.func] = push!(get(c_funcs, frame.func, []), ip)
    end

    functions = values(julia_functions) ∪ values(c_functions)
    sort!(functions, by=nsamples, rev=true)

    total_samples = length(data.ips) + length(data.c_ips)
    menu = ProfileMenu(functions, total_samples)

    while (choice = request("Profiler", menu)) != -1
        paged_io() do (io)
            showprofile(io, data, functions[choice])
        end
        println()
    end

    return
end

function print_header(io, mi::Core.MethodInstance, nsamples, ntotal)
    fname, line = functionloc_safe(mi)

    path = length(relpath(fname)) < length(fname) ? relpath(fname) : fname
    dirname, file = splitdir(path)

    print(io, "┌╴ ")
    Base.with_output_color(
        (_io) -> Base.show_tuple_as_call(_io, mi.def.name, mi.specTypes; qualified=true),
        :light_cyan, io,
        bold=true
    )
    println(io)

    print(io, "├╴ ")
    printstyled(io, dirname * Base.Filesystem.pathsep(), color=:light_black)
    printstyled(io, file, bold=true)
    printstyled(io, ":$(line)\n", color=:light_black)

    print(io, "├╴ ")
    samplepct = round(100 * nsamples / ntotal, digits=1)
    printstyled(io, "$nsamples samples ($(samplepct)%)\n", color=:light_black)
end

function showprofile(io, data, pf::ProfiledCFunction)
    ips = pf.ips

    start, stop = extrema(ips)
    freqs = countmap(ips)

    print(io, "┌╴ ")
    printstyled(io, name(pf), color=:light_cyan, bold=true)
    printstyled(io, " (C function)", color=:light_black)
    println(io)
    print(io, "├╴")
    printstyled(io, location(pf), color=:light_black)
    println(io)
    print(io, "├╴")
    nsamples = length(ips)
    samplepct = round(100 * nsamples / (length(data.ips)+length(data.c_ips)), digits=1)
    printstyled(io, "$nsamples samples ($(samplepct)%)\n", color=:light_black)
    print(io, "└───────────────┐ \n")

    ranges = create_addr_ranges(ips)
    for (i, range) in enumerate(ranges)
        # TODO get rid of the plus 4 somehow...
        addrs, instrs = llvm_disassemble_range(llvm_create_disassembler(), range.first, range.second+4)
        for (addr, instr) in zip(addrs, instrs)
            frac = get(freqs, addr, 0) / length(ips)
            color = frac >= 0.05 ? (:red) : (:green)
            prefix = "$(round(frac*100, digits=1))%"
            prefix = lpad(frac == 0 ? "" : prefix, 6)

            printstyled(io, prefix, color=color)
            print(io, " $(string(addr, base=16, pad=8))│")
            printstyled(io, instr, color=(frac == 0 ? :normal : color))
            println(io)
        end

        if i != lastindex(ranges)
            jump = ranges[i+1].first - range.second
            printstyled(io, "       (+$jump)\n", color=:light_black)
        end
    end
end

function showprofile(io, data, pf::ProfiledJuliaFunction)
    lines = map(ip -> lookup(data, ip)[end].line, pf.ips)
    cmap = countmap(pf.ips)
    freqs = countmap(lines)
    total = length(lines)

    mi = pf.mi
    i_indices, i_lines = instructionmap(mi)

    lineinstrs = Dict() # Dict{Int, Vector{String}}()
    for (fptr, asmlines) in zip(i_indices, i_lines)
        res = lookup(data, fptr)

        if res[end].linfo == mi
            line = res[end].line
            if !haskey(lineinstrs, line)
                lineinstrs[line] = [(asmlines, fptr)]
            else
                push!(lineinstrs[line], (asmlines, fptr))
            end
        end
    end

    src, startline = CodeTracking.definition(String, mi.def)

    print_header(io, mi, total, length(data.ips) + length(data.c_ips))

    for (i, linestr) in enumerate(split(src, "\n"))
        lineno = startline + i - 1

        if i == 1
            dashes = "─" ^ (6 + length(string(lineno)))
            print(io, "└$(dashes)┐ \n")
        end

        prefix = ""
        color = :normal
        if haskey(freqs, lineno)
            frac = freqs[lineno]/total
            prefix = "$(round(frac*100, digits=1))%"
            color = frac >= 0.05 ? (:red) : (:green)
        end
        
        prefix = lpad(prefix, 6)

        printstyled(io, "$prefix ", color=:yellow, bold=true)
        print(io, "$(lineno)│ ")
        print(io, "$linestr\n")

        stripped = lstrip(linestr)

        if haskey(freqs, lineno) && haskey(lineinstrs, lineno)
            iter = lineinstrs[lineno]
            for (asmlines, fptr) in iter
                for (i, asmline) in enumerate(asmlines)
                    if length(asmline) == 0 || asmline[1] != ';'
                        asmline = (" " ^ (stripped.offset - linestr.offset)) * lstrip(asmline)
                        
                        if haskey(cmap, fptr)
                            #print(io, cmap[fptr])
                            frac = cmap[fptr] / total
                            color = frac >= 0.05 ? (:red) : (:green)
                            prefix = "$(round(frac*100, digits=1))%"
                            prefix = lpad(prefix, 6)
                            if i == 1
                                printstyled(io, prefix, color=color)
                            elseif i == length(asmline)
                                printstyled(io, "    │ ", color=color)
                            else
                                printstyled(io, "    └─", color=color)
                            end
                        else
                            print(io, "      ")
                        end

                        print(io, " " ^ (1 + ndigits(lineno)))
                        print(io, "│ ")
                        printstyled(io, asmline, color=:light_blue)
                        println(io)
                    end
                end
            end
        end
    end

    println(io)
end

abstract type CodeLocation end

struct PointerCodeLocation <: CodeLocation
    ip::UInt64
end

struct LineCodeLocation <: CodeLocation
    line::Int
end

struct CodeTable{T <: PointerCodeLocation}
    locations::Vector{T}
    code::Vector{Vector{SubString}}
end

function instructionmap(linfo)
    world = Base.get_world_counter()
    str = InteractiveUtils._dump_function_linfo_native(linfo, world, false, :att, :default, true)

    ptr::UInt64 = 0
    indices, lines = UInt64[], Vector{SubString}[]
    for line in split(str, "\n")
        code_origin_match = match(r"^; code origin: ([0-9a-fA-F]+)", line)
        if !isnothing(code_origin_match)
            ptr = parse(UInt64, code_origin_match[1], base=16)
            indices, lines = [ptr], [[line]]
            continue
        end

        instr_addr_match = match(r"^; ([0-9a-fA-F]+): ([0-9a-fA-F]+)", line)
        if !isnothing(instr_addr_match)
            addr = parse(UInt64, instr_addr_match[1], base=16)
            mask = UInt64(0xFFFF)
            ptr = (ptr & ~mask) | (addr & mask)
            if indices[end] != ptr
                push!(indices, ptr)
                push!(lines, [])
            end
        elseif length(line) > 0 && line[1] != ';'
            (ptr != 0) && push!(lines[end], line)
        end

    end

    return indices, lines
end

function thing()
    A = rand(100, 100)
    B = similar(A)
    for i = 1:150
        B = i .+ A^3.14
    end
    return B
end

end # module ProfileTools
