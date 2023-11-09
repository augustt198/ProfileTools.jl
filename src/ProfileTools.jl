module ProfileTools

using Profile
using CodeTracking
using StatsBase
using InteractiveUtils
using REPL.TerminalMenus

include("llvmdis.jl")

export @perf

const IPtr = UInt64

function functionloc_safe(mi)
    try
        fname, line = functionloc(mi)
        fname = isnothing(fname) ? "<unknown>" : fname
        return fname, line
    catch
        return "<unknown>", "<unknown>"
    end
end

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
    fname, line = functionloc_safe(pf.mi)
    return "$fname:$line"
end

@kwdef struct ProfileConfig
    # include C functions in the profile
    cfuncs::Bool = false
    # precompile the function first
    precompile::Bool = true
    # how many trials to run
    trials::Int = 1
    # if positive, keep profiling until this many
    # samples are obtained
    samples::Int = -1
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
    !isempty(bad) && throw(ArgumentError("Unknown arguments: $(join(repr.(bad), ", "))"))

    for (k, v) in kwargs
        typ = fieldtype(ProfileConfig, k)
        (v isa typ) || throw(ArgumentError("Bad argument type: $k (want $typ)"))
    end
    
    return ProfileConfig(; kwargs...)
end

function count_samples_nocopy(start, endd)
    ptr = Profile.get_data_pointer()
    return count(iszero(unsafe_load(ptr, i)) for i = max(1, start):endd) ÷ 2
end

macro perf(expr, args...)
    conf = parse_macro_args(args)

    sym = gensym("profilee")
    fn_def = quote
        @noinline $(sym)() = for i in 1:$(conf.trials)
            Base.donotdelete(@noinline $expr)
        end
    end
    Core.eval(__module__, fn_def)

    quote
        len_start = Profile.len_data()
        $(conf.precompile) && precompile($(esc(sym)), ())
        nsamples = 0
        while true
            this_start = Profile.len_data()
            Profile.@profile $(esc(sym))()

            nsamples += count_samples_nocopy(this_start, Profile.len_data())
            if nsamples >= $(conf.samples)
                break
            end
        end
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

    run(pipeline(io, `less -S -R -P "$title"`))
end

function printperf(conf, len_start, len_end)
    ips = terminalIPs(conf, len_start, len_end)

    doit(conf, ips)
    return
end

struct FrequencyMap{K}
    dict::Dict{K, Int}

    FrequencyMap{K}(d=Dict{K, Int}()) where {K} = new(d)
end

getfreq(fm::FrequencyMap{T}, x::T) where {T} = get(fm.dict, x, 0)
incfreq(fm::FrequencyMap{T}, x::T, inc=1) where {T} = fm.dict[x] = getfreq(fm, x) + inc
merge(a::FrequencyMap{T}, b::FrequencyMap{T}) where {T} = FrequencyMap{T}(mergewith(+)(a.dict, b.dict))

struct ProfileData
    ips::Vector{IPtr}
    c_ips::Vector{IPtr}
    ip2st::Dict{IPtr, Vector{StackTraces.StackFrame}}
    callers::Dict{IPtr, FrequencyMap{IPtr}}

    ProfileData() = new([], [], Dict(), Dict())
end

lookup(data::ProfileData, ip::IPtr) = get!(() -> StackTraces.lookup(ip), data.ip2st, ip)

function terminalIPs(conf, len_start=1, len_end=nothing)
    samples = Profile.fetch(include_meta=true)
    len_end = isnothing(len_end) ? length(samples) : len_end
    samples = @view samples[len_start:len_end]
    samples = Profile.strip_meta(samples)

    data = ProfileData()

    first, second = true, true
    called_ip = 0
    for ip in samples
        # stackwalk.c subtracts one sometimes,
        # so re-align the ip on arm
        (Sys.ARCH == :aarch64) && (ip &= ~3)

        if first
            st = lookup(data, ip)
            if st[end].from_c
                # push the IP if c functions are being recorded
                # otherwise, continue up until a julia IP
                if conf.cfuncs
                    called_ip = ip
                    push!(data.c_ips, ip)
                    first = false
                end
            else
                called_ip = ip
                push!(data.ips, ip)
                first = false
            end
        else
            if second && ip != 0
                fm = get!(() -> FrequencyMap{IPtr}(), data.callers, called_ip)
                incfreq(fm, ip)
            end
            second = false
            (ip == 0) && (first = second = true)
        end
    end

    data
end

function doit(conf, data=terminalIPs(conf))
    functions = ProfiledFunction[]

    julia_functions = Dict{Core.MethodInstance, ProfiledJuliaFunction}()
    for ip in data.ips
        st = lookup(data, ip)
        if !st[end].from_c
            mi = st[end].linfo
            if !isnothing(mi)
                pf = get!(() -> ProfiledJuliaFunction(mi, []), julia_functions, mi)

                push!(pf.ips, ip)
            end
        end
    end

    c_functions = Dict{Symbol, ProfiledCFunction}()
    for ip in data.c_ips
        st = lookup(data, ip)
        frame = st[end]
        name = frame.func
        pf = get!(() -> ProfiledCFunction(name, [], string(frame.file)), c_functions, name)

        push!(pf.ips, ip)
    end

    functions = values(julia_functions) ∪ values(c_functions)
    sort!(functions, by=nsamples, rev=true)

    total_samples = length(data.ips) + length(data.c_ips)
    menu = ProfileMenu(functions, total_samples)

    while (choice = request("Profiler", menu)) != -1
        paged_io() do io
            showprofile(io, data, functions[choice])
        end
        println()
    end

    return
end

function print_header(io, data, pf::ProfiledFunction, ntotal)
    fname = location(pf)

    path = length(relpath(fname)) < length(fname) ? relpath(fname) : fname
    dirname, file = splitdir(path)

    print(io, "┌╴ ")
    if pf isa ProfiledJuliaFunction
        Base.with_output_color(
            (_io) -> Base.show_tuple_as_call(_io, pf.mi.def.name, pf.mi.specTypes; qualified=true),
            :light_cyan, io,
            bold=true
        )
    else
        color = pf isa ProfiledCFunction ? (:light_magenta) : (:light_cyan)
        printstyled(io, name(pf), color=color, bold=true)
        (pf isa ProfiledCFunction) && printstyled(io, " (C function)", color=:light_black)
    end
    println(io)

    print(io, "├╴ ")
    printstyled(io, dirname * Base.Filesystem.pathsep(), color=:light_black)
    parts = split(file, ':', limit=2)
    printstyled(io, parts[1], bold=true)

    (length(parts) > 1) && printstyled(io, ":$(parts[2])", color=:light_black)
    println(io)

    print(io, "├╴ ")
    samplepct = round(100 * nsamples(pf) / ntotal, digits=1)
    printstyled(io, "$(nsamples(pf)) samples ($(samplepct)% of total)\n", color=:light_black)

    if pf isa ProfiledJuliaFunction
        print(io, "├╴ ")
        fptr = string(UInt64(pf.mi.cache.specptr), base=16, pad=16)
        printstyled(io, "Code address 0x$fptr\n", color=:light_black)
    end

    fm = reduce(merge, [get(() -> FrequencyMap{IPtr}(), data.callers, ip) for ip in unique(pf.ips)])

    print(io, "├╴ ")
    printstyled(io, "Callers: $(isempty(fm.dict) ? "unknown" : "")\n", color=:light_black)

    fm′ = FrequencyMap{Tuple{Symbol, Symbol, Int}}()
    for (ip, count) in fm.dict
        frame = lookup(data, ip)[end]
        incfreq(fm′, (frame.func, frame.file, frame.line), count)
    end

    sorted_fm′ = sort(collect(fm′.dict), by = p -> p.second, rev=true)
    for (tup, count) in sorted_fm′
        func, file, line = tup
        samplepct = round(100 * count / nsamples(pf), digits=1)
        line = (line >= 0) ? line : "?"
        print(io, "│    ")
        printstyled(io, "($(samplepct)%) ", color=:light_black)
        printstyled(io, "$(func) ")
        printstyled(io, "in $(splitdir(string(file))[2]):$(line)", color=:light_black)
        println(io)
    end
end

function showasm(io, data, iptrs, lineinstrs, lineno, cmap, total, offset=0)
    iter = lineinstrs[lineno]
    prev_stack = Base.StackFrame[]

    lastaddr = 0
    for (asmlines, iptr) in iter
        j′ = 0

        idx = searchsortedlast(iptrs, iptr - 1)
        if lastaddr != 0 && idx > 0
            if iptrs[idx] != lastaddr
                # there's a gap in the instructions
                gap = iptr - lastaddr
                print(io, " " ^ (7 + ndigits(lineno)))
                print(io, "│ ")
                print(io, " " ^ (offset + 44))
                printstyled(io, lpad("(+$gap)", 10), color=:light_black)
                println(io)
            end
        end
        lastaddr = iptr

        for (j, asmline) in enumerate(asmlines)
            if length(asmline) == 0 || asmline[1] != ';'
                j′ += 1

                asmline_parts = split(strip(asmline), '\t', limit=2)
                asmline = rpad(asmline_parts[1], 8) * join(asmline_parts[2:end])
                asmline_length = length(asmline)
                asmline = (" " ^ offset) * asmline
                
                if haskey(cmap, iptr)
                    frac = cmap[iptr] / total
                    color = frac >= 0.05 ? (:red) : (:green)
                    prefix = "$(round(frac*100, digits=1))%"
                    prefix = lpad(prefix, 6)
                    if j′ == 1
                        printstyled(io, prefix, color=color)
                    elseif j == length(asmline)
                        printstyled(io, "    └─", color=color)
                    else
                        printstyled(io, "    │ ", color=color)
                    end
                else
                    print(io, "      ")
                end

                print(io, " " ^ (1 + ndigits(lineno)))
                print(io, "│ ")
                printstyled(io, asmline, color=:light_blue)
                print(io, " " ^ (50 - asmline_length))
                
                printg(s) = printstyled(io, s, color=:light_black)
                printg(string(iptr & 0xFFFF, base=16, pad=4))
                printg("┊")

                # draw the inlining stack info
                stack = @view lookup(data, iptr)[1:end-1]

                function print_tree_lines(frames)
                    for fidx in reverse(keys(frames))
                        frame = frames[fidx]
                        len = length(string(frame.func))
                        print(io, " " ^ (2 + len))

                        (fidx != 1) && printg("│")
                    end
                end

                if stack != prev_stack
                    l = min(length(stack), length(prev_stack))
                    mismatch = findfirst(j -> stack[end-j] != prev_stack[end-j], 0:l-1)
                    mismatch = isnothing(mismatch) ? 0 : mismatch - 1

                    print_tree_lines(@view prev_stack[end-mismatch+1:end])

                    (mismatch > 0) && printg("├")
                    for frame in reverse(stack[1:end-mismatch])
                        printstyled(io, " $(frame.func) ", color=:light_black, bold=true)
                        if frame == stack[1]
                            printg("┐")
                            printg("  ($(splitdir(string(frame.file))[2]):$(frame.line))")
                        else
                            printg("┬")
                        end
                    end

                    prev_stack = stack
                else
                    print_tree_lines(prev_stack)
                    !isempty(prev_stack) && printg("│")
                end

                println(io)
            end
        end
    end
end

function showprofile(io, data, pf::ProfiledCFunction)
    ips = pf.ips
    freqs = countmap(ips)

    print_header(io, data, pf, length(data.ips) + length(data.c_ips))

    print(io, "└───────────────┐ \n")

    ranges = create_addr_ranges(ips)
    for (i, range) in enumerate(ranges)
        # TODO get rid of the plus 4 (arch dependent)
        result = llvm_disassemble_range(llvm_create_disassembler(), range.first, range.second+4)
        if isnothing(result)
            printstyled(io, "Failed to disassemble address range: $range\n", color=:red, bold=true)
            continue
        end

        addrs, instrs = result
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
    # make this less silly
    lines = map(ip -> lookup(data, ip)[end].line, pf.ips)
    cmap = countmap(pf.ips)
    freqs = countmap(lines)
    total = length(lines)

    mi = pf.mi
    i_indices, i_lines = instructionmap(mi)

    lineinstrs = Dict()
    for (iptr, asmlines) in zip(i_indices, i_lines)
        res = lookup(data, iptr)

        if res[end].linfo == mi
            line = res[end].line
            if !haskey(lineinstrs, line)
                lineinstrs[line] = [(asmlines, iptr)]
            else
                push!(lineinstrs[line], (asmlines, iptr))
            end
        end
    end

    codedef = CodeTracking.definition(String, mi.def)
    if isnothing(codedef)
        printstyled(io, "ERROR: could not find method definiton", color=:red, bold=true)
        println(io)
        return
    else
        src, startline = codedef
    end

    print_header(io, data, pf, length(data.ips) + length(data.c_ips))

    lineno = 0
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

        offset = (lstrip(linestr).offset - linestr.offset)

        if haskey(freqs, lineno) && haskey(lineinstrs, lineno)
            showasm(io, data, i_indices, lineinstrs, lineno, cmap, total, offset)
        end
    end

    println(io)

    linerange = startline:lineno
    any_excluded = false
    for (line, _) in lineinstrs
        if line ∉ linerange
            if !any_excluded
                printstyled(io, "Unassigned instructions:\n", bold=true)
                any_excluded = true
            end

            showasm(io, data, i_indices, lineinstrs, line, cmap, total)
        end
    end
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

end # module ProfileTools
